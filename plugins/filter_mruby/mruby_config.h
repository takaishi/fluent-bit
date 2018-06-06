#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_sds.h>

#include "mruby.h"
#include "mruby/compile.h"
#include "mruby/string.h"

struct mruby_filter {
    struct mrb_state *mrb;
};