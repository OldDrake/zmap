/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include "../fieldset.h"
#include "output_modules.h"

int csv4rdns_init(struct state_conf *conf, char **fields, int fieldlens);
int csv4rdns_process(fieldset_t *fs);
int csv4rdns_close(struct state_conf *c, struct state_send *s, struct state_recv *r);