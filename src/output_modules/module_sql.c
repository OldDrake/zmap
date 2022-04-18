/*
 * ZMap Copyright 2013 Regents of the University of Michigan
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy
 * of the License at http://www.apache.org/licenses/LICENSE-2.0
 */

#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <assert.h>
#include <inttypes.h>
#include <mysql/mysql.h>

#include "../../lib/logger.h"
#include "../fieldset.h"

#include "output_modules.h"

#define DEFAULT_ADDR "localhost"
#define DEFAULT_USER "root"
#define DEFAULT_PWD "root"
#define DEFAULT_DATABASE "rdns_scan"
#define DEFAULT_TABLE "zmap_result"

struct SQL_Info {
	char* addr;
	char* user;
	char* pwd;
	char* database;
	char* table;
};


static MYSQL* conn;
static struct SQL_Info sql_info;
static int saddr_index = -1;
static int data_index = -1;


//sql info format:  addr:user:pwd:database:table
int parse_SQL_info(char* str) {
	char* p;
    int cnt = 0;
    p = str;
    while(*p != '\0'){
        if(*p == ':')
            cnt++;
        p++;
    }
    if(cnt != 4) return 0;
	p = str;
	sql_info.addr = str;
	for (; (*p != ':') && (*p != '\0'); p++);
	*p = '\0'; p++;
	sql_info.user = p;
	for (; (*p != ':') && (*p != '\0'); p++);
	*p = '\0'; p++;
	sql_info.pwd = p;
	for (; (*p != ':') && (*p != '\0'); p++);
	*p = '\0'; p++;
	sql_info.database = p;
	for (; (*p != ':') && (*p != '\0'); p++);
	*p = '\0'; p++;
	sql_info.table = p;
	return 1;
}

int sql_init(struct state_conf *conf, char **fields, int fieldlens)
{
    assert(conf);
    sql_info.addr = DEFAULT_ADDR;
    sql_info.user = DEFAULT_USER;
    sql_info.pwd = DEFAULT_PWD;
    sql_info.database = DEFAULT_DATABASE;
    sql_info.table = DEFAULT_TABLE;

    if(conf->output_filename){
        parse_SQL_info(conf->output_filename);
    }
    if(!(conn = mysql_init(NULL))){
        printf("mysql初始化失败！\n");
        return 1;
    }
    if(!(conn = mysql_real_connect(conn, sql_info.addr, sql_info.user, sql_info.pwd, sql_info.database, 0, NULL, 0))){
        printf("数据库连接失败！\n");
        return 2;
    }

    if (!conf->no_header_row) {
        // save the saddr field index and data field index 
		for (int i = 0; i < fieldlens; i++) {
            if(!strcmp(fields[i], "saddr"))
                saddr_index = i;
            else if(!strcmp(fields[i], "data")){
                data_index = i;
            }
		}
	}

    return EXIT_SUCCESS;
}

int sql_close(__attribute__((unused)) struct state_conf *c,
	      __attribute__((unused)) struct state_send *s,
	      __attribute__((unused)) struct state_recv *r)
{
	mysql_close(conn);
	return EXIT_SUCCESS;
}

int sql_process(fieldset_t *fs)
{
    char cmd[100];
    MYSQL_RES* result;

    if (!conn || data_index == -1 || saddr_index == -1) {
		return EXIT_SUCCESS;
	}
    // if the response is dns response, print the saddr and the 
    field_t *f = &(fs->fields[data_index]);
    unsigned char *buf = (unsigned char *)f->value.ptr;
    if(dns_confirm_sql((unsigned char *)f->value.ptr, f->len)){
        f = &(fs->fields[saddr_index]);

	    sprintf(cmd, "select * from %s where ip=\"%s\"",sql_info.table,(char*)f->value.ptr);
        mysql_query(conn, cmd);
        result = mysql_store_result(conn);
        if(!mysql_fetch_row(result)){
            sprintf(cmd, "insert into %s (ip,aa,ra,rcode) values (\"%s\",%u,%u,%u)",sql_info.table,(char*)f->value.ptr,((buf[2]&0x04)==0x04),((buf[3]&0x80)==0x80),(buf[3]&0x0f));
            mysql_query(conn, cmd);
        } else {
    		sprintf(cmd, "update %s set aa=%u,ra=%u,rcode=%u where ip=\"%s\"", sql_info.table,((buf[2]&0x04)==0x04),((buf[3]&0x80)==0x80),(buf[3]&0x0f),(char*)f->value.ptr);
            mysql_query(conn, cmd);
        }
    }
    return EXIT_SUCCESS;
}

// confirm the RA bit in the DNS reponse
int dns_confirm_sql(unsigned char *readbuf, size_t len)
{
    if(len < 12)
        return 0;
    if((readbuf[2]&0x80) == 0x80)
        return 1;
    else
        return 0;
}

output_module_t module_sql_file = {
    .name = "sql",
    .init = &sql_init,
    .start = NULL,
    .update = NULL,
    .update_interval = 0,
    .close = &sql_close,
    .process_ip = &sql_process,
    .supports_dynamic_output = NO_DYNAMIC_SUPPORT,
    .helptext =
	"Saving outputs to mysql."
};
