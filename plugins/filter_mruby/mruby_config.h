#include <fluent-bit/flb_info.h>
#include <fluent-bit/flb_filter.h>
#include <fluent-bit/flb_luajit.h>
#include <fluent-bit/flb_sds.h>

#include "mruby.h"
#include "mruby/compile.h"
#include "mruby/string.h"

typedef struct mf_t {
    double ts;
    char *tag;
    msgpack_object *record;
    struct mrb_state *mrb;

} mf;

struct mruby_filter {
    flb_sds_t script;
    flb_sds_t call;
    struct mf_t *mf;
};

MRB_API mrb_value mrb_str_new_cstr(mrb_state*, const char*);
mrb_value msgpack_obj_to_mrb_value(mrb_state*, msgpack_object*);
