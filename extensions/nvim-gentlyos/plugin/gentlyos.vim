" GentlyOS Neovim Plugin
" Distributed intelligence with BONEBLOB optimization

if exists('g:loaded_gentlyos')
  finish
endif
let g:loaded_gentlyos = 1

" Default configuration
if !exists('g:gentlyos_provider')
  let g:gentlyos_provider = 'claude'
endif

if !exists('g:gentlyos_boneblob_enabled')
  let g:gentlyos_boneblob_enabled = 1
endif

if !exists('g:gentlyos_auto_start')
  let g:gentlyos_auto_start = 1
endif

" Lazy load the plugin
augroup GentlyOS
  autocmd!
  autocmd VimEnter * lua require('gentlyos').setup({
        \ provider = vim.g.gentlyos_provider,
        \ boneblob = { enabled = vim.g.gentlyos_boneblob_enabled == 1 },
        \ mcp = { auto_start = vim.g.gentlyos_auto_start == 1 },
        \ })
augroup END
