//
//  main.cpp
//  sambaclient
//
//  Created by Jon Nermut on 23/08/13.
//  Copyright (c) 2013 AsdeqLabs. All rights reserved.
//


#include <netinet/in.h>
#include <iostream>
#include <iomanip>
#include "libsmbclient.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory>
#include "talloc.h"
#include "smbheader.h"
#include "security.h"

#include <vector>
#include <algorithm>

#define NOT_IMPLEMENTED 3221225659

#define NT_STATUS_BROKEN_PIPE 3221225803

#define BROKEN_PIPE 32

using namespace std;

const int BUFFER_SIZE = 4096;

int	debuglevel	= 5;
const char	*workgroup	= "NT";
const char	*username	= "guest";
const char	*password	= "";

bool supportsPolicy = true;

TALLOC_CTX *talloc_tos(void);

void printError(int err, string path, string msg)
{
    cerr << "ERROR: " << msg;
    if (!path.empty())
    {
        cerr << " Path:" << path;
    }
    if (errno != 0)
    {
        cerr << " Error Number: " << err << " : " << strerror(err);
        
    }
    cerr << endl;
}

void delete_smbctx(SMBCCTX* ctx)
{
    smbc_getFunctionPurgeCachedServers(ctx)(ctx);
    smbc_free_context(ctx, 1);
}

void printErrorAndExit(int err, string path, string msg, SMBCCTX* ctx)
{
    printError(err, path, msg);
    if (ctx!=NULL)
    {
        delete_smbctx(ctx);
    }
    exit(err);
}



void smbc_auth_fn(
                  const char      *server,
                  const char      *share,
                  char            *wrkgrp, int wrkgrplen,
                  char            *user,   int userlen,
                  char            *passwd, int passwdlen)
{
    
    (void) server;
    (void) share;
    (void) wrkgrp;
    (void) wrkgrplen;
    
    strncpy(wrkgrp, workgroup, wrkgrplen - 1); wrkgrp[wrkgrplen - 1] = 0;
    strncpy(user, username, userlen - 1); user[userlen - 1] = 0;
    strncpy(passwd, password, passwdlen - 1); passwd[passwdlen - 1] = 0;
}



SMBCCTX* create_smbctx()
{
    SMBCCTX	*ctx;
    
    int err = smbc_init(smbc_auth_fn, debuglevel);
    if (err != 0)
    {
        printErrorAndExit(err, "", "Could not initialize smbclient library.", NULL);
    }
    ctx = smbc_set_context(NULL);
    
    smbc_setDebug(ctx, debuglevel);
    
    smbc_setOptionFullTimeNames(ctx, 1);

    //smbc_setOptionUseKerberos(ctx, 1);
	//smbc_setOptionFallbackAfterKerberos(ctx, 1);
    
    smbc_setOptionNoAutoAnonymousLogin(ctx, 0);
    smbc_setOptionUseCCache(ctx, 1);
    smbc_setOptionSmbEncryptionLevel(ctx, SMBC_ENCRYPTLEVEL_NONE);
    //smbc_setOptionCaseSensitive(ctx, 0);
        
    // one connection per server
    smbc_setOptionOneSharePerServer(ctx, 1);
    smbc_setOptionUseCCache(ctx, 1);
    return ctx;
}


void writeEscapedString(ostream& ss, const string& str)
{
    //ss << "\"";
    for (size_t i = 0; i < str.length(); ++i)
    {
        unsigned char chr = str[i];
        if (chr < '\x20') 
        {
            ss << "\\u" << std::setfill('0') << std::setw(4) << std::hex << chr;
        }
//        else if ( chr == '\\')
//        {
//            ss << "\\\\";
//        }
//        else if (chr == '"')
//        {
//            ss << "\\\"";
//        }
        else
        {
            ss << chr;
        }
    }
    //ss << "\"";
}

void writeKeyVal(ostream& out, const string& key, string& val)
{
    out << key << ": ";
    writeEscapedString(out, val);
    out << endl;
}

void writeKeyVal(ostream& out, const string& key, long val)
{
    out << key << ": " << val << endl;;
    
}


/*****************************************************
 Return a connection to a server.
 *******************************************************/
static struct cli_state* connect_one(string server, string share)
{
    
	NTSTATUS nt_status;
    int retry=0;
    do
    {
        // retry a few times if we get a broken pipe
        retry++;
        struct cli_state *c = NULL;
        struct sockaddr_storage ss;

        uint32_t flags = 0;
        // apparently we need to zero the sockaddr structure otherwise stuff breaks
        zero_sockaddr(&ss);

        // connects to the share - signing state is on
        nt_status = cli_full_connection(&c, "AsdeqDocs Server", server.c_str(),
                                        &ss,
                                        0,
                                        share.c_str(),
                                        "?????",
                                        username,
                                        workgroup,
                                        password,
                                        flags,
                                        1);
        
        if (NT_STATUS_IS_OK(nt_status))
        {
            return c;
        }
    }
    while (nt_status==NT_STATUS_BROKEN_PIPE && retry < 5);
	return NULL;
}

/*****************************************************
 get sec desc for filename
 *******************************************************/

static struct security_descriptor *get_secdesc(struct cli_state *cli, const char *filename)
{
	uint16_t fnum = (uint16_t)-1;
	struct security_descriptor *sd;
	NTSTATUS status;
    
	/* The desired access below is the only one I could find that works
     with NT4, W2KP and Samba */
    
	status = cli_ntcreate(cli, filename, 0, READ_CONTROL_ACCESS,
                          0, FILE_SHARE_READ|FILE_SHARE_WRITE,
                          FILE_OPEN, 0x0, 0x0, &fnum);
	if (!NT_STATUS_IS_OK(status))
    {
		printf("\nFailed to open %s: %s\n", filename, nt_errstr(status));
		return NULL;
	}
    
	sd = cli_query_secdesc(cli, fnum, talloc_tos());
    
	cli_close(cli, fnum);
    
	if (!sd)
    {
		printf("\nFailed to get security descriptor\n");
		return NULL;
	}
    return sd;
}

/*****************************************************
look up the sid
 *******************************************************/

static NTSTATUS cli_lsa_lookup_sid(struct cli_state *cli,
                                   const struct dom_sid *sid,
                                   TALLOC_CTX *mem_ctx,
                                   enum lsa_SidType *type,
                                   char **domain, char **name)
{
	// if policy connection fails then do keep try as it seems to upset OSX
    if (supportsPolicy)
    {
        uint16 orig_cnum = cli->cnum;
        struct rpc_pipe_client *p = NULL;
        struct policy_handle handle;
        NTSTATUS status;
        TALLOC_CTX *frame = talloc_stackframe();
        enum lsa_SidType *types;
        char **domains;
        char **names;
        
        status = cli_tcon_andx(cli, "IPC$", "?????", "", 0);
        if (!NT_STATUS_IS_OK(status)) {
            return status;
        }
        
        status = cli_rpc_pipe_open_noauth(cli, &ndr_table_lsarpc.syntax_id,
                                          &p);
        if (!NT_STATUS_IS_OK(status)) {
            goto fail;
        }
        
        status = rpccli_lsa_open_policy(p, talloc_tos(), true,
                                        GENERIC_EXECUTE_ACCESS, &handle);
        if (!NT_STATUS_IS_OK(status))
        {
            // if it fails once avoid calling this method again as I'm sure all the RPC stuff is screwing OSX more.
            if (status==NOT_IMPLEMENTED)
            {
                supportsPolicy = false;
            }
            goto fail;
        }
        
        status = rpccli_lsa_lookup_sids(p, talloc_tos(), &handle, 1, sid,
                                        &domains, &names, &types);
        if (!NT_STATUS_IS_OK(status)) {
            goto fail;
        }
        
        *type = types[0];
        *domain = talloc_move(mem_ctx, &domains[0]);
        *name = talloc_move(mem_ctx, &names[0]);
        
        status = NT_STATUS_OK;
    fail:
        TALLOC_FREE(p);
        cli_tdis(cli);
        cli->cnum = orig_cnum;
        TALLOC_FREE(frame);
        return status;
    }
    return NOT_IMPLEMENTED;
}




/* print an ACE on a FILE, using either numeric or ascii representation */
static void print_ace(struct cli_state *cli, FILE *f, struct security_ace *ace)
{
	
	fstring sidstr;

    sid_to_fstring(sidstr, &ace->trustee);
    
	fprintf(f, "%s", sidstr);
    
    // numeric ace
    
    char *domain = NULL;
	char *name = NULL;
	enum lsa_SidType type;
	NTSTATUS status;

    
    status = cli_lsa_lookup_sid(cli, &ace->trustee, talloc_tos(), &type,
                                &domain, &name);
    
	if (NT_STATUS_IS_OK(status))
    {
	    
        if (*domain)
        {
            //slprintf(sidstr, sizeof(fstring) - 1, "%s%s%s",
            //         domain, '\\', name);
            fprintf(f, "|%s\\%s", domain, name);
        }
        else
        {
            //fstrcpy(sidstr, name);
            fprintf(f, "|%s", name);
        }
        
    }
    
	//fprintf(f, "%d/0x%x/0x%08x", ace->type, ace->flags, ace->access_mask);
    fprintf(f, ":%d/%d/0x%08x", ace->type, ace->flags, ace->access_mask);
    
    return;
}



void enumerate(ostream& out, SMBCCTX *ctx, struct cli_state *cli, bool recursive, bool acls, bool children, string path)
{
    TALLOC_CTX *frame = talloc_stackframe();
    
    //char buffer[32768 * 10];
    
    struct stat     st;
    
    
    SMBCFILE		*fd;
    struct smbc_dirent	*dirent;

    // if we just want the node then we filter on the entry.
    // this could probably be optimised.
    string filterName;
    if (!children)
    {
        long posn = path.find_last_of("/", path.length()-2);
        filterName = path.substr(posn+1, string::npos);
        path = path.substr(0, posn);
        // if last char is a slash then remove it.
        if ( *(filterName.end()-1)=='/')
            filterName.pop_back();
    }
    // on a broken pipe retry a couple of times
    int retry=0;
    do
    {
        retry++;
        fd = smbc_getFunctionOpendir(ctx)(ctx, path.c_str());
    }
    while (errno==BROKEN_PIPE && retry<5);
    
    if (fd == NULL)
    {
        printError(errno, path, "Could not open path to enumerate.");
    }
    else
    {
        // keep a list of children to enumerate so we can close handles before calling recursive
        std::vector<string> childrenToEnumerate;
        
        
        while((dirent = smbc_getFunctionReaddir(ctx)(ctx, fd)) != NULL)
        {

            
            string name = dirent->name;
            int type = dirent->smbc_type;
            if (filterName.length()==0 || (filterName.compare(name)==0 && (type==SMBC_DIR || type==SMBC_FILE_SHARE)))
            {
            
                if (name.empty() || name == "." || name == "..")
                    continue;

                string fullPath = path;
                if (fullPath.empty() || fullPath[fullPath.length() - 1] != '/')
                {
                    fullPath += "/";
                }
                fullPath +=  name;
                

                
                
                switch (type)
                {
                    case SMBC_WORKGROUP:
                    case SMBC_SERVER:
                    

                        writeKeyVal(out, "url", fullPath);
                        writeKeyVal(out, "name", name);
                        writeKeyVal(out, "type", type);
                    
                        break;
                    case SMBC_FILE_SHARE:
                    case SMBC_DIR:
                    case SMBC_FILE:
                        

                        writeKeyVal(out, "url", fullPath);
                        writeKeyVal(out, "name", name);

                        writeKeyVal(out, "type", type);
                        if (type!=SMBC_FILE_SHARE)
                        {
                            if (smbc_stat(fullPath.c_str(), &st) < 0)
                            {
                                printError(errno, fullPath, "Could not get attributes of path.");
                                
                            }
                            else
                            {
                                writeKeyVal(out, "size", st.st_size);
                                writeKeyVal(out, "lastmod", st.st_mtimespec.tv_sec);                    

                            }
                        }
                        // windows seems to have stopped resolving these sid attributes for some reason
                        if (acls)
                        {
                           // we just use the low level api's to resolve this now - since it works on both Apple and Windows
                            // however apple can't resolve the usernames
                            
                            if (!cli)
                            {
                                // fails with a segmentation fault if we try to get acl's off a fileshare node
                                // usually the cli structure will work? but it all depends on magic.
                               /* - this code doesn't work on OSX
                                if (type!=SMBC_FILE_SHARE)
                                {
                                    const char* the_acl = strdup("system.nt_sec_desc.*+");
                                    //const char* the_acl = "system.nt_sec_desc.*"; // "system.nt_sec_desc.*+";
                                    const char *url = fullPath.c_str();
                                    
                                    int ret = smbc_getxattr(url, the_acl, buffer, sizeof(buffer));
                                    if (ret == 0)                   
                                    {
                                        string str = buffer;
                                        writeKeyVal(out, "xattr", str );
                                        
                                    }
                                    
                                    const char* the_aclSid = strdup("system.nt_sec_desc.*");
                                    // try to read the sids from the attributes, if this doesn't work then we can call
                                    // the security discriptor function which seems to work okay on OS X.
                                    ret = smbc_getxattr(url, the_aclSid, buffer, sizeof(buffer));
                                    if (ret == 0)
                                    {
                                        string str = buffer;
                                        writeKeyVal(out, "xattrSid", str );                                
                                    }
                                }
                                */
                            }
                            else
                            {
                                // OSX Specific to get the ACL's from the file.
                                
                                // calculate share path - parse the two first tokens and throw away
                                strtok(strdup(fullPath.substr(6, string::npos).c_str()), "/");
                                strtok(NULL, "/");
                                string filePath = "";
                                char *pch = strtok(NULL, "/");
                                
                                while (pch!=NULL)
                                {
                                    filePath+="\\";
                                    filePath +=pch;
                                    pch = strtok(NULL, "/");
                                }

                                // we use fprintf C functions from the adapted sample code.
                                // I could have rewritten it but in the interest of getting it working I left it as is.
                                fprintf(stdout, "xattrSid: ");
                                // this gets the security descriptor from the file
                                security_descriptor* sd = get_secdesc(cli, filePath.c_str());
                                if (sd)
                                {                        
                                    // enumerate and print the aces to stdout
                                    for (int i = 0; sd->dacl && i < sd->dacl->num_aces; i++)
                                    {                                                        
                                        struct security_ace *ace = &sd->dacl->aces[i];
                                        if (i>0)
                                            fprintf(stdout, ",");
                                        fprintf(stdout, "ACL:");
                                        print_ace(cli, stdout, ace);
                                
                                    }
                                }
                                fprintf(stdout, "\n");
                                
                                
                            }
                        }
                        
                }
                
                // handle recursive
                if (recursive && type != SMBC_FILE && children)
                {
                    childrenToEnumerate.push_back(fullPath);
                }
                if (filterName.length()>0)
                    break;        
            }
            
            
        }
        // close dir try to avoid having open fd handles to prevent OSX from getting upset.
        if (fd)
        {
            smbc_getFunctionClose(ctx)(ctx, fd);
        }
        // enumerate children
        for (auto subPath : childrenToEnumerate)
        {        
            enumerate(out, ctx, cli, recursive, acls, true, subPath);
        }
    }
    // do we need to close our cli connection?
    TALLOC_FREE(frame);
}

void read(string path, SMBCCTX *ctx)
{
    char buffer[BUFFER_SIZE];
    int fd;
    long ret;
    int savedErrno;
    
    if ((fd = smbc_open(path.c_str(), O_RDONLY, 0)) < 0)
    {
        printErrorAndExit(errno, path, "Could not open file for reading.", ctx);
    }
    
    do
    {
        ret = smbc_read(fd, buffer,  BUFFER_SIZE);
        savedErrno = errno;
        if (ret > 0)
        {
            fwrite(buffer, 1, ret, stdout);
        }
        
    } while (ret > 0);
    
    smbc_close(fd);
    
    if (ret < 0)
    {
        errno = savedErrno;
        printErrorAndExit(savedErrno, path, "Error reading file.", ctx);
    }
}

void write(string path, SMBCCTX	*ctx)
{
   
    char buffer[BUFFER_SIZE];
    int fd;
    long ret;
    int savedErrno;
    
    fd = smbc_open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0);
    if (fd < 0)
    {
        printErrorAndExit(fd, path, "Could not open file for writing.", ctx);
    }
    
    while(!feof(stdin))
    {
        size_t bytes = fread(buffer,1,BUFFER_SIZE,stdin);
        
        ret = smbc_write(fd, buffer, bytes);
        savedErrno = errno;

        if (savedErrno < 0 || ret < 0)
            printErrorAndExit(savedErrno, path, "Failed to write bytes to file.", ctx);
    }
    
    ret = smbc_close(fd);
    if (ret < 0)
    {
        printErrorAndExit((int)ret, path, "Error closing file for write.", ctx);
    }
}






int main(int argc, const char * argv[])
{
    
    TALLOC_CTX *frame = talloc_stackframe();
    
    string susername;
    string spassword;
    string path;
    string command;
    
    if (argc >= 4)
    {
        susername = argv[1];
        spassword = argv[2];
        path = argv[3];
        command = argv[4];
    }
    else
    {
        cerr << "Usage: sambaclient username password smbpath command\n";
        exit(1);
        
    }
    

    
    workgroup = "";
    username = susername.c_str();
    password = spassword.c_str();
    
    SMBCCTX	*ctx = create_smbctx();    
    
    
    if (command == "version")
    {
        const char* version = smbc_version();
        cout << "Samba version: " << version << endl;
    }
    else if (command.find("enumerate") != string::npos)
    {
        bool acls = command.find("acls") != string::npos;
        bool children = command.find("children") != string::npos;
        bool recursive = command.find("recursive") != string::npos;
        
        
        // open second connection for apple ACL's - horrible but this is where we ended up
        
        struct cli_state *cli = NULL;
        TALLOC_CTX *frame = talloc_stackframe();
        // format connection strings

        char *server = strtok(strdup(path.substr(6, string::npos).c_str()), "/");
        char *share = strtok(NULL, "/");
        // connect if we have enough information
        
        if (server && share)
        {
            cli = connect_one(server, share );
        }
        // if we aren't connecting to a share but enumerating the server then we don't need cli
        if (!cli && server && share)
        {
            // usually a broken pipe
            printErrorAndExit(-1, path, "Error opening connection to enumerate ACL's.", ctx);
        }
        else
        {
            enumerate(cout, ctx, cli, recursive, acls, children, path);
            
            if (cli)
                cli_shutdown(cli);
        }
        TALLOC_FREE(frame);

        
    }
    else if (command == "read")
    {
        read(path, ctx);
    }
    else if (command == "write")
    {
        write(path, ctx);
    }
    

    
    delete_smbctx(ctx);
    
    TALLOC_FREE(frame);
    return 0;
}


