---@mod gentlyos GentlyOS Neovim Plugin
---@brief [[
--- GentlyOS integration for Neovim
--- Provides AI-powered code assistance with BONEBLOB optimization
--- and token-secure communication via MCP
---@brief ]]

local M = {}

-- Configuration defaults
M.config = {
    provider = "claude",
    boneblob = {
        enabled = true,
        passes = 5,
    },
    security = {
        token_watchdog = true,
        mask_tokens = true,
        sanitize_responses = true,
    },
    mcp = {
        auto_start = true,
        timeout = 30000,
    },
    keymaps = {
        chat = "<leader>gc",
        explain = "<leader>ge",
        refactor = "<leader>gr",
        test = "<leader>gt",
        toggle_boneblob = "<leader>gb",
    },
}

-- State
local state = {
    mcp_job = nil,
    connected = false,
    request_id = 0,
    pending = {},
    history = {},
    security_log = {},
}

-- Token patterns from gently-security
local TOKEN_PATTERNS = {
    { name = "anthropic", pattern = "sk%-ant%-api%d%d%-[A-Za-z0-9_-]+", mask = "sk-ant-***" },
    { name = "openai", pattern = "sk%-[A-Za-z0-9]+", mask = "sk-***" },
    { name = "github", pattern = "gh[po]_[A-Za-z0-9]+", mask = "gh*_***" },
    { name = "aws", pattern = "AKIA[A-Z0-9]+", mask = "AKIA***" },
    { name = "groq", pattern = "gsk_[A-Za-z0-9]+", mask = "gsk_***" },
}

-- Prompt injection patterns
local INJECTION_PATTERNS = {
    "ignore%s+previous%s+instructions",
    "disregard%s+prior",
    "forget%s+everything",
    "you%s+are%s+now%s+DAN",
    "jailbreak",
    "<%|im_start%|>",
    "<<SYS>>",
}

---@param text string
---@return string masked
local function mask_tokens(text)
    if not M.config.security.mask_tokens then
        return text
    end

    local masked = text
    for _, pattern in ipairs(TOKEN_PATTERNS) do
        masked = masked:gsub(pattern.pattern, pattern.mask)
    end
    return masked
end

---@param text string
---@return string[] detected
local function detect_credentials(text)
    local detected = {}
    for _, pattern in ipairs(TOKEN_PATTERNS) do
        if text:match(pattern.pattern) then
            table.insert(detected, pattern.name)
        end
    end
    return detected
end

---@param text string
---@return boolean
local function detect_injection(text)
    local lower = text:lower()
    for _, pattern in ipairs(INJECTION_PATTERNS) do
        if lower:match(pattern) then
            return true
        end
    end
    return false
end

---@param event table
local function log_security_event(event)
    event.timestamp = os.date("%Y-%m-%d %H:%M:%S")
    table.insert(state.security_log, event)

    -- Keep last 1000 events
    if #state.security_log > 1000 then
        table.remove(state.security_log, 1)
    end

    -- Notify on critical
    if event.severity == "critical" then
        vim.notify("[GentlyOS Security] " .. event.message, vim.log.levels.WARN)
    end
end

---@param text string
---@return string sanitized, string[] warnings
local function sanitize_input(text)
    local warnings = {}

    -- Check for credentials
    local creds = detect_credentials(text)
    if #creds > 0 and M.config.security.token_watchdog then
        table.insert(warnings, "Input contains " .. table.concat(creds, ", ") .. " credential(s)")
        log_security_event({
            type = "credential_leak",
            severity = "warning",
            message = "Credentials detected in input: " .. table.concat(creds, ", "),
        })
    end

    return text, warnings
end

---@param text string
---@return string sanitized, string[] warnings
local function sanitize_response(text)
    local warnings = {}

    if not M.config.security.sanitize_responses then
        return text, warnings
    end

    -- Mask any leaked credentials
    local creds = detect_credentials(text)
    if #creds > 0 then
        table.insert(warnings, "Response contained credentials - masked")
        text = mask_tokens(text)
        log_security_event({
            type = "credential_leak",
            severity = "warning",
            message = "Credentials in response: " .. table.concat(creds, ", "),
        })
    end

    -- Check for injection patterns
    if detect_injection(text) then
        table.insert(warnings, "Response contained injection patterns")
        log_security_event({
            type = "injection_attempt",
            severity = "warning",
            message = "Injection patterns detected in response",
        })
    end

    return text, warnings
end

-- MCP Communication

---@param method string
---@param params table?
---@param callback function
local function mcp_request(method, params, callback)
    if not state.connected then
        callback(nil, "MCP not connected")
        return
    end

    state.request_id = state.request_id + 1
    local id = state.request_id

    local request = vim.json.encode({
        jsonrpc = "2.0",
        id = id,
        method = method,
        params = params or {},
    })

    state.pending[id] = callback

    -- Send to MCP process
    if state.mcp_job then
        vim.fn.chansend(state.mcp_job, request .. "\n")
    end

    -- Timeout
    vim.defer_fn(function()
        if state.pending[id] then
            state.pending[id] = nil
            callback(nil, "Request timeout")
        end
    end, M.config.mcp.timeout)
end

---@param data string
local function handle_mcp_response(data)
    -- Handle newline-separated JSON
    for line in data:gmatch("[^\n]+") do
        local ok, response = pcall(vim.json.decode, line)
        if ok and response.id then
            local callback = state.pending[response.id]
            if callback then
                state.pending[response.id] = nil
                if response.error then
                    callback(nil, response.error.message)
                else
                    callback(response.result, nil)
                end
            end
        end
    end
end

-- Start MCP server
function M.start_mcp()
    if state.mcp_job then
        return
    end

    state.mcp_job = vim.fn.jobstart({ "gently", "mcp", "serve", "--json" }, {
        on_stdout = function(_, data)
            if data then
                handle_mcp_response(table.concat(data, "\n"))
            end
        end,
        on_stderr = function(_, data)
            if data and data[1] ~= "" then
                vim.notify("[GentlyOS MCP] " .. mask_tokens(table.concat(data, "\n")), vim.log.levels.DEBUG)
            end
        end,
        on_exit = function(_, code)
            state.mcp_job = nil
            state.connected = false
            if code ~= 0 then
                vim.notify("[GentlyOS] MCP server exited with code " .. code, vim.log.levels.WARN)
            end
        end,
    })

    if state.mcp_job > 0 then
        state.connected = true
        vim.notify("[GentlyOS] MCP server started", vim.log.levels.INFO)
    else
        vim.notify("[GentlyOS] Failed to start MCP server. Is 'gently' installed?", vim.log.levels.ERROR)
    end
end

-- Stop MCP server
function M.stop_mcp()
    if state.mcp_job then
        vim.fn.jobstop(state.mcp_job)
        state.mcp_job = nil
        state.connected = false
    end
end

-- Chat API

---@param messages table[]
---@param callback function
function M.chat(messages, callback)
    -- Sanitize messages
    local sanitized = {}
    for _, msg in ipairs(messages) do
        local text, warnings = sanitize_input(msg.content)
        if #warnings > 0 then
            vim.notify("[GentlyOS Security] " .. table.concat(warnings, "; "), vim.log.levels.WARN)
        end
        table.insert(sanitized, { role = msg.role, content = text })
    end

    mcp_request("tools/call", {
        name = "chat",
        arguments = {
            messages = sanitized,
            provider = M.config.provider,
            boneblob = M.config.boneblob.enabled,
        },
    }, function(result, err)
        if err then
            callback(nil, err)
            return
        end

        -- Sanitize response
        local text, warnings = sanitize_response(result.text or "")
        if #warnings > 0 then
            vim.notify("[GentlyOS Security] " .. table.concat(warnings, "; "), vim.log.levels.WARN)
        end

        callback({
            text = text,
            tokens_used = result.tokens_used,
            provider = result.provider,
        }, nil)
    end)
end

-- Commands

---@param prompt string
function M.explain(prompt)
    local messages = {
        { role = "user", content = "Explain this code:\n\n```\n" .. prompt .. "\n```" },
    }

    M.chat(messages, function(result, err)
        if err then
            vim.notify("[GentlyOS] Error: " .. err, vim.log.levels.ERROR)
            return
        end

        -- Open result in split
        vim.cmd("vsplit")
        local buf = vim.api.nvim_create_buf(false, true)
        vim.api.nvim_set_current_buf(buf)
        vim.api.nvim_buf_set_option(buf, "filetype", "markdown")
        vim.api.nvim_buf_set_lines(buf, 0, -1, false, vim.split(result.text, "\n"))
        vim.api.nvim_buf_set_option(buf, "modifiable", false)
    end)
end

---@param prompt string
function M.refactor(prompt)
    local messages = {
        { role = "user", content = "Suggest refactoring for this code. Provide improved version:\n\n```\n" .. prompt .. "\n```" },
    }

    M.chat(messages, function(result, err)
        if err then
            vim.notify("[GentlyOS] Error: " .. err, vim.log.levels.ERROR)
            return
        end

        vim.cmd("vsplit")
        local buf = vim.api.nvim_create_buf(false, true)
        vim.api.nvim_set_current_buf(buf)
        vim.api.nvim_buf_set_option(buf, "filetype", "markdown")
        vim.api.nvim_buf_set_lines(buf, 0, -1, false, vim.split(result.text, "\n"))
        vim.api.nvim_buf_set_option(buf, "modifiable", false)
    end)
end

---@param prompt string
function M.generate_tests(prompt)
    local messages = {
        { role = "user", content = "Generate unit tests for this code:\n\n```\n" .. prompt .. "\n```" },
    }

    M.chat(messages, function(result, err)
        if err then
            vim.notify("[GentlyOS] Error: " .. err, vim.log.levels.ERROR)
            return
        end

        vim.cmd("vsplit")
        local buf = vim.api.nvim_create_buf(false, true)
        vim.api.nvim_set_current_buf(buf)
        vim.api.nvim_buf_set_option(buf, "filetype", "markdown")
        vim.api.nvim_buf_set_lines(buf, 0, -1, false, vim.split(result.text, "\n"))
        vim.api.nvim_buf_set_option(buf, "modifiable", false)
    end)
end

function M.toggle_boneblob()
    M.config.boneblob.enabled = not M.config.boneblob.enabled
    vim.notify("[GentlyOS] BONEBLOB " .. (M.config.boneblob.enabled and "enabled" or "disabled"), vim.log.levels.INFO)
end

function M.security_status()
    local recent = {}
    for i = math.max(1, #state.security_log - 10), #state.security_log do
        if state.security_log[i] then
            table.insert(recent, state.security_log[i])
        end
    end

    local lines = {
        "GentlyOS Security Status",
        "========================",
        "",
        "Token Watchdog: " .. (M.config.security.token_watchdog and "ON" or "OFF"),
        "Response Sanitization: " .. (M.config.security.sanitize_responses and "ON" or "OFF"),
        "Token Masking: " .. (M.config.security.mask_tokens and "ON" or "OFF"),
        "",
        "Recent Events (" .. #state.security_log .. " total):",
    }

    for _, event in ipairs(recent) do
        table.insert(lines, string.format("  [%s] %s: %s", event.severity, event.type, event.message))
    end

    vim.cmd("vsplit")
    local buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_set_current_buf(buf)
    vim.api.nvim_buf_set_lines(buf, 0, -1, false, lines)
    vim.api.nvim_buf_set_option(buf, "modifiable", false)
end

-- Setup

---@param opts table?
function M.setup(opts)
    M.config = vim.tbl_deep_extend("force", M.config, opts or {})

    -- Auto-start MCP
    if M.config.mcp.auto_start then
        vim.defer_fn(M.start_mcp, 100)
    end

    -- Register commands
    vim.api.nvim_create_user_command("GentlyChat", function()
        require("gentlyos.chat").open()
    end, {})

    vim.api.nvim_create_user_command("GentlyExplain", function()
        local lines = vim.api.nvim_buf_get_lines(0, vim.fn.line("'<") - 1, vim.fn.line("'>"), false)
        M.explain(table.concat(lines, "\n"))
    end, { range = true })

    vim.api.nvim_create_user_command("GentlyRefactor", function()
        local lines = vim.api.nvim_buf_get_lines(0, vim.fn.line("'<") - 1, vim.fn.line("'>"), false)
        M.refactor(table.concat(lines, "\n"))
    end, { range = true })

    vim.api.nvim_create_user_command("GentlyTest", function()
        local lines = vim.api.nvim_buf_get_lines(0, vim.fn.line("'<") - 1, vim.fn.line("'>"), false)
        M.generate_tests(table.concat(lines, "\n"))
    end, { range = true })

    vim.api.nvim_create_user_command("GentlyBoneblob", M.toggle_boneblob, {})

    vim.api.nvim_create_user_command("GentlySecurity", M.security_status, {})

    -- Keymaps
    local km = M.config.keymaps
    vim.keymap.set("n", km.chat, ":GentlyChat<CR>", { silent = true, desc = "GentlyOS Chat" })
    vim.keymap.set("v", km.explain, ":GentlyExplain<CR>", { silent = true, desc = "GentlyOS Explain" })
    vim.keymap.set("v", km.refactor, ":GentlyRefactor<CR>", { silent = true, desc = "GentlyOS Refactor" })
    vim.keymap.set("v", km.test, ":GentlyTest<CR>", { silent = true, desc = "GentlyOS Generate Tests" })
    vim.keymap.set("n", km.toggle_boneblob, ":GentlyBoneblob<CR>", { silent = true, desc = "Toggle BONEBLOB" })

    -- Cleanup on exit
    vim.api.nvim_create_autocmd("VimLeavePre", {
        callback = M.stop_mcp,
    })

    vim.notify("[GentlyOS] Plugin loaded", vim.log.levels.INFO)
end

return M
