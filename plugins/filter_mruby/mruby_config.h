#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_sds.h>

#include "mruby.h"
#include "mruby/compile.h"
#include "mruby/string.h"

typedef struct mf_t {
    int count;
    double ts;
    char *tag;
    msgpack_object *record;
    struct mrb_state *mrb;

} mf;

struct mruby_filter {
    struct mf_t *mf;
};