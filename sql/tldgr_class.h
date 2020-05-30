/*
 * tldgr_class.h
 *
 *  Created on: 2019. 3. 12.
 *      Author: tledger
 */

#ifndef SQL_TLDGR_CLASS_H_
#define SQL_TLDGR_CLASS_H_

#include "mariadb.h"
#include "violite.h"                            /* SSL_type */
#include "sql_trigger.h"
#include "thr_lock.h"                  /* thr_lock_type, TL_UNLOCK */
#include "mem_root_array.h"
#include "sql_cmd.h"
#include "sql_alter.h"                // Alter_info
#include "sql_window.h"
#include "sql_trigger.h"
#include "sp.h"                       // enum stored_procedure_type
#include "sql_tvc.h"
#include "sql_class.h"
#include "sql_lex.h"
#include "handler.h"
#include "../include/clog.h"


#define TLEDGER_BASE_VERSION	"TLEDGER-1.0"
#define TLDEGER_VERSION_ID		010000
#define TLEDGER_BASE_MARIADB_VERSION "mariadb-10.3"
#define TLEDGER_BASE_MARIADB_VERSION_ID 100311
#define TLEDGER_TLC_VERSION		1

#define TLDGR_TLC_HEADER_SIZE	1024
#define TLDGR_MAX_SIG_FIELDS	255
#define TLDGR_MAX_CREATE_IMAGE_SIZE	4096

#define TLDGR_CNF_FILE_EXT ".tlc"
#define TLDGR_FLAG_OFFSET  1



struct st_tldg_sig_info {
	LEX_CSTRING sig_name;
	unsigned int input_no;
	LEX_CSTRING *input_field_name;
};


// See. PKCS#11... below is just temporary mechanism parameters.
struct st_dsa_mechanism {
	LEX_CSTRING mechanism_name;
	unsigned int mechanism_id;
	unsigned int parameter1;
	unsigned int parameter2;
};


static ha_create_table_option create_trusted_table_options[] = {
		{HA_OPTION_TYPE_STRING,"TRUSTED_ORDERER_MASTER_PUB_KEY",sizeof("TRUSTED_ORDERER_MASTER_PUB_KEY"),    0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TRUSTED_ORDERER_SUB_PUB_KEY",sizeof("TRUSTED_ORDERER_SUB_PUB_KEY"),    0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TABLE_ISSUER_PUB_KEY",sizeof("TABLE_ISSUER_PUB_KEY"),          0,0,0,0,0,0,0 },
   	    {HA_OPTION_TYPE_STRING,"TABLE_CREATE_STMT_TRANSFORMED",sizeof("TABLE_CREATE_STMT_TRANSFORMED"),          0,0,0,0,0,0,0 },		
		{HA_OPTION_TYPE_STRING,"TABLE_ISSUER_TABLE_IMAGE_SIGN",sizeof("TABLE_ISSUER_TABLE_IMAGE_SIGN"),        0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"DSA_SCHEME",sizeof("DSA_SCHEME"),  0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_STRING,"TABLE_CHILD_PUB_KEY",sizeof("TABLE_CHILD_PUB_KEY"),        0,0,0,0,0,0,0 },
		{HA_OPTION_TYPE_ULL,0,0,                                   0,0,0,0,0,0,0 }
};


enum  Verification_key_type { TABLE_ISSUER_KEY, FIXED_KEY, INTERNAL_COLUMN_KEY, REFERENCE_KEY};
enum  Sig_field_type { sign_only_field, sign_ordered_field };

#pragma pack(push,1)
class Sig_field_info : public Sql_alloc {
public:
	LEX_CSTRING sig_name;
	LEX_CSTRING sig_column_name;
	unsigned int input_fields_no;
	LEX_CSTRING *input_fields;
	enum  Verification_key_type verification_key_type;
	LEX_CSTRING fixed_verification_key;
	LEX_CSTRING reference_table_name;
	LEX_CSTRING reference_table_column_name;
	enum Sig_field_type sig_field_type;
	LEX_CSTRING order_column_name;
	LEX_CSTRING verification_column_name;
};
#pragma pack(pop)

class LEX_sig_field_info : public Sql_alloc {
public:
	LEX_CSTRING sig_name;
	LEX_CSTRING sig_column_name;
	List<Item>  input_fields;
	enum  Verification_key_type verification_key_type;
	LEX_CSTRING fixed_verification_key = {0,0};
	LEX_CSTRING reference_table_name;
	LEX_CSTRING reference_table_column_name;
	enum Sig_field_type sig_field_type;
	LEX_CSTRING order_column_name = {0,0};
	LEX_CSTRING verification_column_name = {0,0};
	
	void set_sig_name(LEX_CSTRING *sname, LEX_CSTRING *fname) {
		sig_name = *sname;
		sig_column_name= *fname;
	}

	void set_sig_name(LEX_CSTRING *fname) {
		sig_column_name= *fname;
	}

	void set_order_column_name(LEX_CSTRING *sname, LEX_CSTRING *oname) {
		sig_name = *sname;
		order_column_name= *oname;
		sig_field_type = sign_ordered_field;
	}

	void set_verification_column_name(LEX_CSTRING *vname) {
		verification_column_name= *vname;
		verification_key_type = INTERNAL_COLUMN_KEY;
	}
	

	bool add_sig_input_field(THD *thd, Item *item);
	bool set_fixed_field_verification_key_value(LEX_CSTRING * key_value);
};


class Table_trust_options : public Sql_alloc {
public:
	ha_create_table_option *table_options=create_trusted_table_options; // table level options TOS_M_PRK,TOS_S_PRK,TI_PRK, TI_SIGN
	
	unsigned char Tlc_version;
	unsigned int  Dsa_algorithm_type;  // we need to make it abstract function, verify, sign and so on...
	st_dsa_mechanism Dsa_mechanism;

	uint Trusted_table_type;	// 0 : It's not trusted Table  1: Trusted only 2: Trusted & Ordered

	LEX_CSTRING Table_issuer_pubk={0,0};	
	LEX_CSTRING Trusted_orderer_master_pubk={0,0};
	LEX_CSTRING Trusted_orderer_sub_pubk={0,0};
	LEX_CSTRING Table_image={0,0};
	LEX_CSTRING Table_issuer_tableimage_sign={0,0};
	LEX_CSTRING Table_child_pubk={0,0};

	unsigned char  sig_field_infos_no;
	Sig_field_info *sig_field_info_list;

	LEX_CSTRING get_field_option(THD *thd, LEX_CSTRING field_name);
	LEX_CSTRING get_order_option(THD *thd, LEX_CSTRING field_name);

	// we need to make it abstract function, verify, sign and so on...
};



class LEX_trust_options : public Table_trust_options {
public:	
	List<LEX_sig_field_info> list_lex_sig_field_info;
	LEX_trust_options(uint t_type) {
		Trusted_table_type=t_type;
	}

	bool add_sig_field_info(THD *thd, LEX_sig_field_info *sig_field);
};



// 
bool verify_record_sign(THD *thd, TABLE *table, List<Item> &fields, List<Item> &values);


bool tldgr_create_tld_image(THD *thd, const LEX_CSTRING *db, const LEX_CSTRING *table_name, List<Create_field> &create_fields, KEY **key_info, uint *key_count,LEX_CUSTRING *tld_image);

bool tldgr_trust_options_precheck(THD *thd, const LEX_CSTRING *table_name, List<Create_field> &create_fields, KEY **key_info, uint *key_count);

LEX_CUSTRING tldgr_const4t_build_image(LEX_trust_options *trust_options, List<Create_field> &create_fields, KEY **key_info, uint *key_count);

bool tldgr_add_const4t_table(THD *thd, const char *frm, size_t frm_length, const char *path, const char *db, const char *table_name);

//bool init_tldg_from_full_binary_frm_image(TABLE_SHARE*share,const uchar *frm_image);

bool init_share_from_tld_image(THD *thd, TABLE_SHARE*share, const uchar *tld_image, size_t tld_length);

//bool tldgr_parse_option_list(THD* thd, engine_option_value **option_list, ha_create_table_option *rules, engine_option_value **unparsed_option_list,bool suppress_warning, MEM_ROOT *root);
bool tldgr_parse_option_list(THD* thd, engine_option_value **option_list);

bool trusted_table_exists(THD* thd, const LEX_CSTRING *db, const LEX_CSTRING *table_name);

Item *transform_text_for_sign(THD *thd, Item *inval);

bool verify_string(THD *thd, LEX_CSTRING inText, LEX_CSTRING pubKey, LEX_CSTRING signVal);

int check_table_definition_trusted(THD *thd, LEX_CSTRING *db_name, LEX_CSTRING *table_name, LEX_CSTRING child_issuer_key);



void hex2bin(const char* in, size_t len, unsigned char* out);
#endif /* SQL_TLDGR_CLASS_H_ */
