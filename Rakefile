task :preview do
  command = 'jekyll serve --baseurl "" --drafts --watch --config _config.yml'
  command << ',_config_win.yml' if Gem.win_platform?
  system command
end
