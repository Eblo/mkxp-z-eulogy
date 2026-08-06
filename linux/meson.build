swarg = ''
if steamworks == true
  swarg = steam_libpath
endif

if get_option('appimage') == true
  install_data('AppRun')
  install_data('mkxp-z.png')
  install_data('mkxp-z.desktop')

  meson.add_install_script('make_appimg.sh', meson.project_name(), get_option('appimagekit_path'), swarg)
else
  if sizeof['long'] == 8
    archarg = '64'
  else
    archarg = '32'
  endif

  exe_name = meson.project_name() +  '.' + host_machine.cpu()
  if steamworks == true
      exe_name = 'steam_' + exe_name
  endif

  meson.add_install_script('install.sh', exe_name, swarg)
endif
