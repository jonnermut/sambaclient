//
//  main.cpp
//  sambaclient
//
//  Created by Jon Nermut on 23/08/13.
//  Copyright (c) 2013 AsdeqLabs. All rights reserved.
//

#include <iostream>
#include <iomanip>
#include "libsmbclient.h"

#include <stdio.h>
#include <stdlib.h>
#include <memory>

using namespace std;

const int BUFFER_SIZE = 4096;

int	debuglevel	= 0;
const char	*workgroup	= "NT";
const char	*username	= "guest";
const char	*password	= "";



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
    
    //if ((ctx = smbc_new_context()) == NULL)
    //    return NULL;
    
    
    int err = smbc_init(smbc_auth_fn, debuglevel);
    if (err != 0)
    {
        printErrorAndExit(err, "", "Could not initialize smbclient library.");
    }
    ctx = smbc_set_context(NULL);
    
    smbc_setDebug(ctx, debuglevel);
    //smbc_setFunctionAuthData(ctx, smbc_auth_fn);
    
    /*
    if (smbc_init_context(ctx) == NULL)
    {
        smbc_free_context(ctx, 1);
        return NULL;
    }
     */
    
    smbc_setOptionFullTimeNames(ctx, 1);
    //smbc_setOptionUseKerberos(ctx, 1);
	//smbc_setOptionFallbackAfterKerberos(ctx, 1);
    
    smbc_setOptionNoAutoAnonymousLogin(ctx, 0);    
    smbc_setOptionUseCCache(ctx, 1);
    
    //smbc_setOptionDebugToStderr(ctx,1);
    //smbc_setNetbiosName(ctx, "edgesouth");
    
    
    /** Set the workgroup used for making connections */
    
    //smbc_setWorkgroup(ctx, "edgesouth.com");
    
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


void enumerate(ostream& out, SMBCCTX *ctx, bool recursive, bool acls, string path)
{
    char buffer[32768 * 10];
    
    struct stat     st;
    
    
    SMBCFILE		*fd;
    struct smbc_dirent	*dirent;


    fd = smbc_getFunctionOpendir(ctx)(ctx, path.c_str());
    if (fd == NULL)
        printErrorAndExit(errno, path, "Could not open path to enumerate.");
    
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
                    if (ret < 0)
                    {
                        printError(errno, path, "Could not read ACL.");
                        
                    }
                    else
                    {
                        string str = buffer;
                        writeKeyVal(out, "xattr", str );
                        
                    }
                    
                    const char* the_aclSid = strdup("system.nt_sec_desc.*");
                    
                    ret = smbc_getxattr(url, the_aclSid, buffer, sizeof(buffer));
                    if (ret < 0)
                    {
                        printError(errno, path, "Could not read ACL.");
                        
                    }
                    else
                    {
                        string str = buffer;
                        writeKeyVal(out, "xattrSid", str );
                        
                    }
                    
                }
                
                // list all attributes
                string attrList = buffer;
                if (smbc_listxattr(fullPath.c_str(),
                                  buffer,
                                  sizeof(buffer)) == 0 )
                {
                    writeKeyVal(out, "attrs", attrList);
                }
                else
                {
                    printError(errno, fullPath, "Could not read xattr list.");
                }
                
                
                if (recursive && type != SMBC_FILE)
                {
                    enumerate(out, ctx, recursive, acls, fullPath);
                }
                break;
        
        }

        
    }
    smbc_getFunctionClose(ctx)(ctx, fd);


}



void read(string path)
{
    char buffer[BUFFER_SIZE];
    int fd;
    int ret;
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
    int ret;
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
        printErrorAndExit(ret, path, "Error closing file for write.");
    }
}


int main(int argc, const char * argv[])
{
    
    
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
    
    return 0;
}


