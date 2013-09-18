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


using namespace std;

const int BUFFER_SIZE = 4096;

int	debuglevel	= 0;
const char	*workgroup	= "NT";
const char	*username	= "guest";
const char	*password	= "";

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

void printErrorAndExit(int err, string path, string msg)
{
    printError(err, path, msg);
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
        printErrorAndExit(err, "", "Could not initialize smbclient library.");
    }
    ctx = smbc_set_context(NULL);
    
    smbc_setDebug(ctx, debuglevel);
    
    smbc_setOptionFullTimeNames(ctx, 1);

//  smbc_setOptionUseKerberos(ctx, 1);
//	smbc_setOptionFallbackAfterKerberos(ctx, 1);
    
    smbc_setOptionNoAutoAnonymousLogin(ctx, 1);
    smbc_setOptionUseCCache(ctx, 1);
    smbc_setOptionSmbEncryptionLevel(ctx, SMBC_ENCRYPTLEVEL_REQUEST);
    //smbc_setOptionCaseSensitive(ctx, 0);
    
    // one connection per server
    smbc_setOptionOneSharePerServer(ctx,0);
    return ctx;
}

void delete_smbctx(SMBCCTX* ctx)
{
    smbc_getFunctionPurgeCachedServers(ctx)(ctx);
    smbc_free_context(ctx, 1);
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
	struct cli_state *c = NULL;
	struct sockaddr_storage ss;
	NTSTATUS nt_status;
	uint32_t flags = 0;
    // apparently we need to zero the sockaddr structure otherwise stuff breaks
	zero_sockaddr(&ss);

    // connects to the share
	nt_status = cli_full_connection(&c, "AsdeqDocs Server", server.c_str(),
                                    &ss,
                                    0,
                                    share.c_str(),
                                    "?????",
                                    username,
                                    workgroup,
                                    password,
                                    flags,
                                    0);
    
    
	if (!NT_STATUS_IS_OK(nt_status))
    {
		return NULL;
	}

	return c;
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
	if (!NT_STATUS_IS_OK(status)) {
		printf("Failed to open %s: %s\n", filename, nt_errstr(status));
		return NULL;
	}
    
	sd = cli_query_secdesc(cli, fnum, talloc_tos());
    
	cli_close(cli, fnum);
    
	if (!sd) {
		printf("Failed to get security descriptor\n");
		return NULL;
	}
    return sd;
}



/* print an ACE on a FILE, using either numeric or ascii representation */
static void print_ace(struct cli_state *cli, FILE *f, struct security_ace *ace)
{
	
	fstring sidstr;
//	SidToString(cli, sidstr, &ace->trustee);
    sid_to_fstring(sidstr, &ace->trustee);
    
	fprintf(f, "%s:", sidstr);
    
    // numeric ace
    
	//fprintf(f, "%d/0x%x/0x%08x", ace->type, ace->flags, ace->access_mask);
    fprintf(f, "%d/%d/0x%08x", ace->type, ace->flags, ace->access_mask);
    
    return;
}



void enumerate(ostream& out, SMBCCTX *ctx, bool recursive, bool acls, string path)
{
    char buffer[32768 * 10];
    
    struct stat     st;
    
    
    SMBCFILE		*fd;
    struct smbc_dirent	*dirent;


    fd = smbc_getFunctionOpendir(ctx)(ctx, path.c_str());
    if (fd == NULL)
        printErrorAndExit(errno, path, "Could not open path to enumerate.");
    
    // open second connection for apple ACL's - horrible but this is where we ended up
    
    struct cli_state *cli;
    TALLOC_CTX *frame = talloc_stackframe();
    // format connection strings
    char *server = strtok(strdup(path.substr(6, string::npos).c_str()), "/");
    char *share = strtok(NULL, "/");    
    // connect if we have enough information
    if (server && share)
    {
        cli = connect_one( server, share );
    }
    while((dirent = smbc_getFunctionReaddir(ctx)(ctx, fd)) != NULL)
    {
        
        
        string name = dirent->name;
        
        if (name.empty() || name == "." || name == "..")
            continue;

        string fullPath = path;
        if (fullPath.empty() || fullPath[fullPath.length() - 1] != '/')
        {
            fullPath += "/";
        }
        fullPath +=  name;
        
        int type = dirent->smbc_type;
        
        
        switch (type)
        {
            case SMBC_WORKGROUP:
            case SMBC_SERVER:
            case SMBC_FILE_SHARE:

                writeKeyVal(out, "url", fullPath);
                writeKeyVal(out, "name", name);
                writeKeyVal(out, "type", type);
                
                break;
                
            case SMBC_DIR:
            case SMBC_FILE:
                

                writeKeyVal(out, "url", fullPath);
                writeKeyVal(out, "name", name);

                writeKeyVal(out, "type", type);
                
                if (smbc_stat(fullPath.c_str(), &st) < 0)
                {
                    printError(errno, fullPath, "Could not get attributes of path.");
                    
                }
                else
                {
                    writeKeyVal(out, "size", st.st_size);
                    writeKeyVal(out, "lastmod", st.st_mtimespec.tv_sec);                    

                }
                
                if (acls)
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
                    else if (cli)
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
                
                                
                // handle recursive
                if (recursive && type != SMBC_FILE)
                {
                    enumerate(out, ctx, recursive, acls, fullPath);
                }
                break;
        
        }

        
    }
    
    TALLOC_FREE(frame);
    
    smbc_getFunctionClose(ctx)(ctx, fd);

    

}

void read(string path)
{
    char buffer[BUFFER_SIZE];
    int fd;
    long ret;
    int savedErrno;
    
    if ((fd = smbc_open(path.c_str(), O_RDONLY, 0)) < 0)
    {
        printErrorAndExit(fd, path, "Could not open file for reading.");
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
        printErrorAndExit(savedErrno, path, "Error reading file.");
    }
}

void write(string path)
{
   
    char buffer[BUFFER_SIZE];
    int fd;
    long ret;
    int savedErrno;
    
    fd = smbc_open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0);
    if (fd < 0)
    {
        printErrorAndExit(fd, path, "Could not open file for writing.");
    }
    
    while(!feof(stdin))
    {
        size_t bytes = fread(buffer,1,BUFFER_SIZE,stdin);
        
        ret = smbc_write(fd, buffer, bytes);
        savedErrno = errno;

        if (savedErrno < 0 || ret < 0)
            printErrorAndExit(savedErrno, path, "Failed to write bytes to file.");
    }
    
    ret = smbc_close(fd);
    if (ret < 0)
    {
        printErrorAndExit((int)ret, path, "Error closing file for write.");
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
        bool recursive = command.find("recursive") != string::npos;
        
        enumerate(cout, ctx, recursive, acls, path);
    }
    else if (command == "read")
    {
        read(path);
    }
    else if (command == "write")
    {
        write(path);
    }
    

    
    delete_smbctx(ctx);
    
    TALLOC_FREE(frame);
    return 0;
}


