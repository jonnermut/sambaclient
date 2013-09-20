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
}
#endif
