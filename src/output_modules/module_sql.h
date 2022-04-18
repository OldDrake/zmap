#include "../fieldset.h"
#include "output_modules.h"


int sql_init(struct state_conf *conf, char **fields, int fieldlens);
int sql_process(fieldset_t *fs);
int sql_close(struct state_conf *c, struct state_send *s, struct state_recv *r);