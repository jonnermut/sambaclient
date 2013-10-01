//
//  smbheader.h
//  sambaclient
//
//  Created by Aaron Scott on 16/09/13.
//  Copyright (c) 2013 AsdeqLabs. All rights reserved.
//
//#include <netinet/in.h>
//#include "network.h"


//#include <sys/socket.h>
//#include <sys/un.h>

//#include <arpa/inet.h>
//#include <netdb.h>
//#include <netinet/tcp.h>

#ifndef sambaclient_smbheader_h
#define sambaclient_smbheader_h

extern "C"
{

#define FSTRING_LEN 256
typedef char fstring[FSTRING_LEN];

// sid type
    
enum lsa_SidType
#ifndef USE_UINT_ENUMS
    {
        SID_NAME_USE_NONE=(int)(0),
        SID_NAME_USER=(int)(1),
        SID_NAME_DOM_GRP=(int)(2),
        SID_NAME_DOMAIN=(int)(3),
        SID_NAME_ALIAS=(int)(4),
        SID_NAME_WKN_GRP=(int)(5),
        SID_NAME_DELETED=(int)(6),
        SID_NAME_INVALID=(int)(7),
        SID_NAME_UNKNOWN=(int)(8),
        SID_NAME_COMPUTER=(int)(9)
    }
#else
    { __donnot_use_enum_lsa_SidType=0x7FFFFFFF}
#define SID_NAME_USE_NONE ( 0 )
#define SID_NAME_USER ( 1 )
#define SID_NAME_DOM_GRP ( 2 )
#define SID_NAME_DOMAIN ( 3 )
#define SID_NAME_ALIAS ( 4 )
#define SID_NAME_WKN_GRP ( 5 )
#define SID_NAME_DELETED ( 6 )
#define SID_NAME_INVALID ( 7 )
#define SID_NAME_UNKNOWN ( 8 )
#define SID_NAME_COMPUTER ( 9 )
#endif
        ;
        
/* ShareAccess field. */
#define FILE_SHARE_NONE 0 /* Cannot be used in bitmask. */
#define FILE_SHARE_READ 1
#define FILE_SHARE_WRITE 2
#define FILE_SHARE_DELETE 4

/* CreateDisposition field. */
#define FILE_SUPERSEDE 0		/* File exists overwrite/supersede. File not exist create. */
#define FILE_OPEN 1			/* File exists open. File not exist fail. */
#define FILE_CREATE 2			/* File exists fail. File not exist create. */
#define FILE_OPEN_IF 3			/* File exists open. File not exist create. */
#define FILE_OVERWRITE 4		/* File exists overwrite. File not exist fail. */
#define FILE_OVERWRITE_IF 5		/* File exists overwrite. File not exist create. */

// conncection flags
#define CLI_FULL_CONNECTION_DONT_SPNEGO 0x0001
#define CLI_FULL_CONNECTION_USE_KERBEROS 0x0002
#define CLI_FULL_CONNECTION_ANONYMOUS_FALLBACK 0x0004
#define CLI_FULL_CONNECTION_FALLBACK_AFTER_KERBEROS 0x0008
#define CLI_FULL_CONNECTION_OPLOCKS 0x0010
#define CLI_FULL_CONNECTION_LEVEL_II_OPLOCKS 0x0020
#define CLI_FULL_CONNECTION_USE_CCACHE 0x0040

    
const int SEC_STD_READ_CONTROL     = 0x00020000;

#define READ_CONTROL_ACCESS  SEC_STD_READ_CONTROL
        
#define GENERIC_EXECUTE_ACCESS SEC_GENERIC_EXECUTE      /* (1<<29) */

#define MAX_NETBIOSNAME_LEN 16
/* DOS character, NetBIOS namestring. Type used on the wire. */
typedef char nstring[MAX_NETBIOSNAME_LEN];

/*
* In this type of allocating functions it is handy to have a general
* TALLOC_CTX type to indicate which parent to put allocated structures on.
*/
typedef void TALLOC_CTX;

/*
 * Create a new talloc stack frame.
 *
 * When free'd, it frees all stack frames that were created after this one and
 * not explicitly freed.
 */

TALLOC_CTX *talloc_stackframe(void);
TALLOC_CTX *talloc_stackframe_pool(size_t poolsize);

/*
 * Get us the current top of the talloc stack.
 */

TALLOC_CTX *talloc_tos(void);

#define NT_STATUS_V(x) (x)

#define likely(x)       (x)

#define NT_STATUS_IS_OK(x) (likely(NT_STATUS_V(x) == 0))

#  define uint16 uint16_t

#  define uint32 uint32_t


//#define sockaddr_storage sockaddr_in6
#define sockaddr_storage sockaddr_in


struct user_auth_info *user_auth_info_init(TALLOC_CTX *mem_ctx);


extern "C" void zero_sockaddr(struct sockaddr_storage *pss);

/* A netbios name structure. */
struct nmb_name {
	nstring      name;
	char         scope[64];
	unsigned int name_type;
};

/* this defines the error codes that receive_smb can put in smb_read_error */
enum smb_read_errors {
	SMB_READ_OK = 0,
	SMB_READ_TIMEOUT,
	SMB_READ_EOF,
	SMB_READ_ERROR,
	SMB_WRITE_ERROR, /* This error code can go into the client smb_rw_error. */
	SMB_READ_BAD_SIG,
	SMB_NO_MEMORY,
	SMB_DO_NOT_DO_TDIS, /* cli_close_connection() check for this when smbfs wants to keep tree connected */
	SMB_READ_BAD_DECRYPT
};

        enum ndr_err_code {
            NDR_ERR_SUCCESS = 0,
            NDR_ERR_ARRAY_SIZE,
            NDR_ERR_BAD_SWITCH,
            NDR_ERR_OFFSET,
            NDR_ERR_RELATIVE,
            NDR_ERR_CHARCNV,
            NDR_ERR_LENGTH,
            NDR_ERR_SUBCONTEXT,
            NDR_ERR_COMPRESSION,
            NDR_ERR_STRING,
            NDR_ERR_VALIDATE,
            NDR_ERR_BUFSIZE,
            NDR_ERR_ALLOC,
            NDR_ERR_RANGE,
            NDR_ERR_TOKEN,
            NDR_ERR_IPV4ADDRESS,
            NDR_ERR_IPV6ADDRESS,
            NDR_ERR_INVALID_POINTER,
            NDR_ERR_UNREAD_BYTES,
            NDR_ERR_NDR64
        };
        
/* used to hold an arbitrary blob of data */
typedef struct datablob {
	uint8_t *data;
	size_t length;
} DATA_BLOB;

typedef uint32_t NTSTATUS;

const char *nt_errstr(NTSTATUS nt_code);

struct GUID {
	uint32_t time_low;
	uint16_t time_mid;
	uint16_t time_hi_and_version;
	uint8_t clock_seq[2];
	uint8_t node[6];
}/* [noprint,gensize,public] */;

struct ndr_syntax_id {
	struct GUID uuid;
	uint32_t if_version;
}/* [public] */;


        /* this is the base structure passed to routines that
         parse MSRPC formatted data
         
         note that in Samba4 we use separate routines and structures for
         MSRPC marshalling and unmarshalling. Also note that these routines
         are being kept deliberately very simple, and are not tied to a
         particular transport
         */
        struct ndr_pull {
            uint32_t flags; /* LIBNDR_FLAG_* */
            uint8_t *data;
            uint32_t data_size;
            uint32_t offset;
            
            uint32_t relative_highest_offset;
            uint32_t relative_base_offset;
            uint32_t relative_rap_convert;
            struct ndr_token_list *relative_base_list;
            
            struct ndr_token_list *relative_list;
            struct ndr_token_list *array_size_list;
            struct ndr_token_list *array_length_list;
            struct ndr_token_list *switch_list;
            
            TALLOC_CTX *current_mem_ctx;
            
            /* this is used to ensure we generate unique reference IDs
             between request and reply */
            uint32_t ptr_count;
        };
        
        /* structure passed to functions that generate NDR formatted data */
        struct ndr_push {
            uint32_t flags; /* LIBNDR_FLAG_* */
            uint8_t *data;
            uint32_t alloc_size;
            uint32_t offset;
            
            uint32_t relative_base_offset;
            uint32_t relative_end_offset;
            struct ndr_token_list *relative_base_list;
            
            struct ndr_token_list *switch_list;
            struct ndr_token_list *relative_list;
            struct ndr_token_list *relative_begin_list;
            struct ndr_token_list *nbt_string_list;
            struct ndr_token_list *dns_string_list;
            struct ndr_token_list *full_ptr_list;
            
            /* this is used to ensure we generate unique reference IDs */
            uint32_t ptr_count;
        };
        
        /* structure passed to functions that print IDL structures */
        struct ndr_print {
            uint32_t flags; /* LIBNDR_FLAG_* */
            uint32_t depth;
            struct ndr_token_list *switch_list;
            void (*print)(struct ndr_print *, const char *, ...) PRINTF_ATTRIBUTE(2,3);
            void *private_data;
            bool no_newline;
        };
    
        /* these are used when generic fn pointers are needed for ndr push/pull fns */
        typedef enum ndr_err_code (*ndr_push_flags_fn_t)(struct ndr_push *, int ndr_flags, const void *);
        typedef enum ndr_err_code (*ndr_pull_flags_fn_t)(struct ndr_pull *, int ndr_flags, void *);
        typedef void (*ndr_print_fn_t)(struct ndr_print *, const char *, const void *);
        typedef void (*ndr_print_function_t)(struct ndr_print *, const char *, int, const void *);
        

        
        struct ndr_interface_call_pipe {
            const char *name;
            const char *chunk_struct_name;
            size_t chunk_struct_size;
            ndr_push_flags_fn_t ndr_push;
            ndr_pull_flags_fn_t ndr_pull;
            ndr_print_fn_t ndr_print;
        };
        
        struct ndr_interface_call_pipes {
            uint32_t num_pipes;
            const struct ndr_interface_call_pipe *pipes;
        };
        
        struct ndr_interface_call {
            const char *name;
            size_t struct_size;
            ndr_push_flags_fn_t ndr_push;
            ndr_pull_flags_fn_t ndr_pull;
            ndr_print_function_t ndr_print;
            struct ndr_interface_call_pipes in_pipes;
            struct ndr_interface_call_pipes out_pipes;
        };
        
        struct ndr_interface_string_array {
            uint32_t count;
            const char * const *names;
        };
        
        struct ndr_interface_table {
            const char *name;
            struct ndr_syntax_id syntax_id;
            const char *helpstring;
            uint32_t num_calls;
            const struct ndr_interface_call *calls;
            const struct ndr_interface_string_array *endpoints;
            const struct ndr_interface_string_array *authservices;
        };
        
        struct ndr_interface_list {
            struct ndr_interface_list *prev, *next;
            const struct ndr_interface_table *table;
        };
        
extern const struct ndr_interface_table ndr_table_lsarpc;        

        
        
        
        
        
        struct policy_handle {
            uint32_t handle_type;
            struct GUID uuid;
        }/* [public] */;
        
struct rpc_pipe_client {
	struct rpc_pipe_client *prev, *next;
    
	struct rpc_cli_transport *transport;
	struct dcerpc_binding_handle *binding_handle;
    
	struct ndr_syntax_id abstract_syntax;
	struct ndr_syntax_id transfer_syntax;
    
	char *desthost;
	char *srv_name_slash;
    
	uint16 max_xmit_frag;
	uint16 max_recv_frag;
    
	struct pipe_auth_data *auth;
    
	/* The following is only non-null on a netlogon client pipe. */
	struct netlogon_creds_CredentialState *dc;
};

struct cli_state {
	/**
	 * A list of subsidiary connections for DFS.
	 */
    struct cli_state *prev, *next;
	int port;
	int fd;
	/* Last read or write error. */
	enum smb_read_errors smb_rw_error;
	uint16 cnum;
	uint16 pid;
	uint16 mid;
	uint16 vuid;
	int protocol;
	int sec_mode;
	int rap_error;
	int privileges;
    
	char *desthost;
    
	/* The credentials used to open the cli_state connection. */
	char *domain;
	char *user_name;
	char *password; /* Can be null to force use of zero NTLMSSP session key. */
    
	/*
	 * The following strings are the
	 * ones returned by the server if
	 * the protocol > NT1.
	 */
	char *server_type;
	char *server_os;
	char *server_domain;
    
	char *share;
	char *dev;
	struct nmb_name called;
	struct nmb_name calling;
	struct sockaddr_storage dest_ss;
    
	DATA_BLOB secblob; /* cryptkey or negTokenInit */
	uint32 sesskey;
	int serverzone;
	uint32 servertime;
	int readbraw_supported;
	int writebraw_supported;
	int timeout; /* in milliseconds. */
	size_t max_xmit;
	size_t max_mux;
	char *outbuf;
	struct cli_state_seqnum *seqnum;
	char *inbuf;
	unsigned int bufsize;
	int initialised;
	int win95;
	bool is_samba;
	bool is_guestlogin;
	uint32 capabilities;
	/* What the server offered. */
	uint32_t server_posix_capabilities;
	/* What the client requested. */
	uint32_t requested_posix_capabilities;
	bool dfsroot;
    
	struct smb_signing_state *signing_state;
    
	struct smb_trans_enc_state *trans_enc_state; /* Setup if we're encrypting SMB's. */
    
	/* the session key for this CLI, outside
     any per-pipe authenticaion */
	DATA_BLOB user_session_key;
    
	/* The list of pipes currently open on this connection. */
	struct rpc_pipe_client *pipe_list;
    
	bool use_kerberos;
	bool fallback_after_kerberos;
	bool use_spnego;
	bool use_ccache;
	bool got_kerberos_mechanism; /* Server supports krb5 in SPNEGO. */
    
	bool use_oplocks; /* should we use oplocks? */
	bool use_level_II_oplocks; /* should we use level II oplocks? */
    
	/* a oplock break request handler */
	NTSTATUS (*oplock_handler)(struct cli_state *cli, uint16_t fnum, unsigned char level);
    
	bool force_dos_errors;
	bool case_sensitive; /* False by default. */
    
	/* Where (if anywhere) this is mounted under DFS. */
	char *dfs_mountpoint;
    
	struct tevent_queue *outgoing;
	struct tevent_req **pending;
};

extern "C" NTSTATUS cli_connect(struct cli_state *cli,
                     const char *host,
                     struct sockaddr_storage *dest_ss);
extern "C" NTSTATUS cli_start_connection(struct cli_state **output_cli,
                              const char *my_name,
                              const char *dest_host,
                              struct sockaddr_storage *dest_ss, int port,
                              int signing_state, int flags);

extern "C" NTSTATUS cli_full_connection(struct cli_state **output_cli,
                             const char *my_name,
                             const char *dest_host,
                             struct sockaddr_storage *dest_ss, int port,
                             const char *service, const char *service_type,
                             const char *user, const char *domain,
                             const char *password, int flags,
                             int signing_state);


extern "C" NTSTATUS cli_ntcreate(struct cli_state *cli,
                      const char *fname,
                      uint32_t CreatFlags,
                      uint32_t DesiredAccess,
                      uint32_t FileAttributes,
                      uint32_t ShareAccess,
                      uint32_t CreateDisposition,
                      uint32_t CreateOptions,
                      uint8_t SecurityFlags,
                      uint16_t *pfid);

struct security_descriptor *cli_query_secdesc(struct cli_state *cli, uint16_t fnum,
                                              TALLOC_CTX *mem_ctx);

NTSTATUS cli_set_secdesc(struct cli_state *cli, uint16_t fnum,
                         struct security_descriptor *sd);

NTSTATUS cli_close(struct cli_state *cli, uint16_t fnum);

    NTSTATUS cli_cm_force_encryption(struct cli_state *c,
                                     const char *username,
                                     const char *password,
                                     const char *domain,
                                     const char *sharename);
    
void cli_shutdown(struct cli_state *cli);
    
char *sid_to_fstring(fstring sidstr_out, const struct dom_sid *sid);

    struct perm_value {
        const char *perm;
        uint32 mask;
    };
    
    /* These values discovered by inspection */
    
    static const struct perm_value special_values[] = {
        { "R", 0x00120089 },
        { "W", 0x00120116 },
        { "X", 0x001200a0 },
        { "D", 0x00010000 },
        { "P", 0x00040000 },
        { "O", 0x00080000 },
        { NULL, 0 },
    };
    
    static const struct perm_value standard_values[] = {
        { "READ",   0x001200a9 },
        { "CHANGE", 0x001301bf },
        { "FULL",   0x001f01ff },
        { NULL, 0 },
    };


NTSTATUS cli_tcon_andx(struct cli_state *cli, const char *share,
                       const char *dev, const char *pass, int passlen);

NTSTATUS cli_tdis(struct cli_state *cli);

    NTSTATUS cli_rpc_pipe_open_noauth(struct cli_state *cli,
                                      const struct ndr_syntax_id *interface,
                                      struct rpc_pipe_client **presult);


    NTSTATUS rpccli_lsa_open_policy(struct rpc_pipe_client *cli,
                                    TALLOC_CTX *mem_ctx,
                                    bool sec_qos, uint32 des_access,
                                    struct policy_handle *pol);

    
    NTSTATUS rpccli_lsa_lookup_names(struct rpc_pipe_client *cli,
                                     TALLOC_CTX *mem_ctx,
                                     struct policy_handle *pol, int num_names,
                                     const char **names,
                                     const char ***dom_names,
                                     int level,
                                     struct dom_sid **sids,
                                     enum lsa_SidType **types);
    
    NTSTATUS rpccli_lsa_lookup_sids(struct rpc_pipe_client *cli,
                                    TALLOC_CTX *mem_ctx,
                                    struct policy_handle *pol,
                                    int num_sids,
                                    const struct dom_sid *sids,
                                    char ***pdomains,
                                    char ***pnames,
                                    enum lsa_SidType **ptypes);
    }
#endif
