---@mod gentlyos.chat GentlyOS Chat Window
---@brief [[
--- Floating window chat interface for GentlyOS
---@brief ]]

local M = {}
local gentlyos = require("gentlyos")

local state = {
    buf = nil,
    win = nil,
    input_buf = nil,
    input_win = nil,
    history = {},
}

local function create_window()
    -- Calculate dimensions
    local width = math.floor(vim.o.columns * 0.8)
    local height = math.floor(vim.o.lines * 0.8)
    local row = math.floor((vim.o.lines - height) / 2)
    local col = math.floor((vim.o.columns - width) / 2)

    -- Create main buffer
    state.buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_option(state.buf, "filetype", "markdown")
    vim.api.nvim_buf_set_option(state.buf, "bufhidden", "wipe")

    -- Create main window
    state.win = vim.api.nvim_open_win(state.buf, true, {
        relative = "editor",
        width = width,
        height = height - 5,
        row = row,
        col = col,
        style = "minimal",
        border = "rounded",
        title = " GentlyOS Chat ",
        title_pos = "center",
    })

    -- Create input buffer
    state.input_buf = vim.api.nvim_create_buf(false, true)
    vim.api.nvim_buf_set_option(state.input_buf, "bufhidden", "wipe")

    -- Create input window
    state.input_win = vim.api.nvim_open_win(state.input_buf, false, {
        relative = "editor",
        width = width,
        height = 3,
        row = row + height - 4,
        col = col,
        style = "minimal",
        border = "rounded",
        title = " Message (Ctrl+Enter to send) ",
        title_pos = "center",
    })

    -- Set up keymaps for input
    vim.api.nvim_buf_set_keymap(state.input_buf, "i", "<C-CR>", "", {
        callback = function()
            M.send()
        end,
    })
    vim.api.nvim_buf_set_keymap(state.input_buf, "n", "<CR>", "", {
        callback = function()
            M.send()
        end,
    })
    vim.api.nvim_buf_set_keymap(state.input_buf, "n", "q", "", {
        callback = M.close,
    })
    vim.api.nvim_buf_set_keymap(state.input_buf, "n", "<Esc>", "", {
        callback = M.close,
    })

    -- Main window keymaps
    vim.api.nvim_buf_set_keymap(state.buf, "n", "q", "", {
        callback = M.close,
    })
    vim.api.nvim_buf_set_keymap(state.buf, "n", "<Esc>", "", {
        callback = M.close,
    })
    vim.api.nvim_buf_set_keymap(state.buf, "n", "i", "", {
        callback = function()
            vim.api.nvim_set_current_win(state.input_win)
            vim.cmd("startinsert")
        end,
    })

    -- Focus input
    vim.api.nvim_set_current_win(state.input_win)
    vim.cmd("startinsert")
end

local function append_message(role, content, meta)
    if not state.buf or not vim.api.nvim_buf_is_valid(state.buf) then
        return
    end

    local lines = {}

    if role == "user" then
        table.insert(lines, "## You")
    else
        local header = "## GentlyOS"
        if meta and meta.provider then
            header = header .. " (" .. meta.provider .. ")"
        end
        table.insert(lines, header)
    end

    table.insert(lines, "")

    for line in content:gmatch("[^\n]+") do
        table.insert(lines, line)
    end

    table.insert(lines, "")

    if meta then
        local info = {}
        if meta.tokens_used then
            table.insert(info, "Tokens: " .. meta.tokens_used)
        end
        if meta.tokens_saved then
            table.insert(info, "Saved: " .. meta.tokens_saved)
        end
        if #info > 0 then
            table.insert(lines, "*" .. table.concat(info, " | ") .. "*")
            table.insert(lines, "")
        end
    end

    table.insert(lines, "---")
    table.insert(lines, "")

    local line_count = vim.api.nvim_buf_line_count(state.buf)
    vim.api.nvim_buf_set_option(state.buf, "modifiable", true)
    vim.api.nvim_buf_set_lines(state.buf, line_count, line_count, false, lines)
    vim.api.nvim_buf_set_option(state.buf, "modifiable", false)

    -- Scroll to bottom
    if state.win and vim.api.nvim_win_is_valid(state.win) then
        vim.api.nvim_win_set_cursor(state.win, { vim.api.nvim_buf_line_count(state.buf), 0 })
    end
end

function M.send()
    if not state.input_buf or not vim.api.nvim_buf_is_valid(state.input_buf) then
        return
    end

    local lines = vim.api.nvim_buf_get_lines(state.input_buf, 0, -1, false)
    local content = table.concat(lines, "\n"):gsub("^%s*(.-)%s*$", "%1")

    if content == "" then
        return
    end

    -- Clear input
    vim.api.nvim_buf_set_lines(state.input_buf, 0, -1, false, {})

    -- Add to history
    table.insert(state.history, { role = "user", content = content })

    -- Show user message
    append_message("user", content)

    -- Show thinking indicator
    append_message("assistant", "_Thinking..._")

    -- Send to GentlyOS
    gentlyos.chat(state.history, function(result, err)
        -- Remove thinking indicator
        if state.buf and vim.api.nvim_buf_is_valid(state.buf) then
            local line_count = vim.api.nvim_buf_line_count(state.buf)
            vim.api.nvim_buf_set_option(state.buf, "modifiable", true)
            -- Remove last 4 lines (thinking message)
            vim.api.nvim_buf_set_lines(state.buf, line_count - 4, line_count, false, {})
            vim.api.nvim_buf_set_option(state.buf, "modifiable", false)
        end

        if err then
            append_message("assistant", "Error: " .. err)
            return
        end

        -- Add to history
        table.insert(state.history, { role = "assistant", content = result.text })

        -- Show response
        append_message("assistant", result.text, {
            provider = result.provider,
            tokens_used = result.tokens_used,
        })
    end)
end

function M.open()
    if state.win and vim.api.nvim_win_is_valid(state.win) then
        vim.api.nvim_set_current_win(state.input_win)
        vim.cmd("startinsert")
        return
    end

    create_window()

    -- Show welcome message
    local welcome = [[
# GentlyOS Chat

Welcome to GentlyOS! AI assistance with BONEBLOB optimization.

**Commands:**
- `i` - Focus input
- `q` or `<Esc>` - Close
- `<C-Enter>` - Send message

**Security:**
- Token watchdog active
- Response sanitization enabled
- Credentials masked in output

---

]]

    vim.api.nvim_buf_set_option(state.buf, "modifiable", true)
    vim.api.nvim_buf_set_lines(state.buf, 0, -1, false, vim.split(welcome, "\n"))
    vim.api.nvim_buf_set_option(state.buf, "modifiable", false)
end

function M.close()
    if state.win and vim.api.nvim_win_is_valid(state.win) then
        vim.api.nvim_win_close(state.win, true)
    end
    if state.input_win and vim.api.nvim_win_is_valid(state.input_win) then
        vim.api.nvim_win_close(state.input_win, true)
    end
    state.win = nil
    state.input_win = nil
    state.buf = nil
    state.input_buf = nil
end

function M.clear_history()
    state.history = {}
end

return M
