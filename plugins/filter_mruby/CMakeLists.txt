set(src
  mruby_config.c
  mruby.c)

FLB_PLUGIN(filter_mruby "${src}" "m")
