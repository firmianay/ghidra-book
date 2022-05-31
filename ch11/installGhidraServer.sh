#!/bin/bash
#
# Copyright (c) 2019 Kara Nance (knance@securityworks.com)
# 
# Permission is hereby granted, free of charge, to any person obtaining a copy of 
# this software and associated documentation files (the "Software"), to deal in 
# the Software without restriction, including without limitation the rights to 
# use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies of 
# the Software, and to permit persons to whom the Software is furnished to do so, 
# subject to the following conditions:
# 
# The above copyright notice and this permission notice shall be included in all 
# copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS 
# FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR 
# COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER 
# IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN 
# CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
# 
# Script to install and create a basic configuration for a Ghidra
# server.
#
# Note that this configuration is suitable for development
# and experimentation purposes only.  If you are configuring a
# Ghidra server for production use you should carefully read the
# Ghidra server documentation found in the Ghidra distribution, and
# determine an appropriate configuration for your environment and
# specific use case.
#

pushd .

#set some environment variables
OWNER=ghidrasrv
SVRROOT=/opt/${OWNER}
REPODIR=/opt/ghidra-repos
GHIDRA_URL=https://ghidra-sre.org/ghidra_9.1_PUBLIC_20191023.zip
GHIDRA_ZIP=/tmp/ghidra.zip

# check to see if the install directory already exists, in which case we
# don't want to install over that with this script (see the instructions for
# uninstalling in the server/svrREADME.html of your Ghidra installation for
# details on how to uninstall Ghidra server before upgrading or moving it
if [ -e ${SVRROOT} ]; then
	echo "${SVRROOT} already exists, so exiting!"
	exit -1
fi

# install required packages, including openjdk 11
sudo apt update && sudo apt install -y openjdk-11-jdk unzip

# make the user that will be used to run the server.
# Ghidra server (or at least the svrAdmin tool) needs there
# to be a home directory
sudo useradd -r -m -d /home/${OWNER} -s /usr/sbin/nologin -U ${OWNER}

# create the directory for the repos
sudo mkdir ${REPODIR}
sudo chown ${OWNER}.${OWNER} ${REPODIR}

# download ghidra server
wget ${GHIDRA_URL} -O ${GHIDRA_ZIP}

# unzip the ghidra code
mkdir /tmp/ghidra && cd /tmp/ghidra && unzip ${GHIDRA_ZIP}

# mv the ghidra code into place
sudo mv ghidra_* ${SVRROOT}

# cleanup /tmp
cd /tmp && rm -f ${GHIDRA_ZIP} && rmdir ghidra

# create a backup of the original server configuration file
cd ${SVRROOT}/server && cp server.conf server.conf.orig

# change the location in which repositories will be saved
REPOVAR=ghidra.repositories.dir
sed -i "s@^$REPOVAR=.*\$@$REPOVAR=$REPODIR@g" server.conf

# Add the -u parameter.  Ghidra Server 9.1 does not like it if
# we have the -u parameter last, so we change parameter.2 to
# parameter.3 then add the new parameter.2=-u before that updated line
PARM=wrapper.app.parameter.
sed -i "s/^${PARM}2=/${PARM}3=/" server.conf
sed -i "/^${PARM}3=/i ${PARM}2=-u" server.conf

# Change the process owner user to ghidrasrv
ACCT=wrapper.app.account
sed -i "s/^.*$ACCT=.*/$ACCT=$OWNER/" server.conf

# all other parameters are being left unchanged for this development/experimental
# installation, but you are strongly advised to read server/svrREADME.html in the
# Ghidra distribution to determine what configurations are appropriate for a
# production deployment

# change ownership of the ghidra server directory to the ghidrasrv user
sudo chown -R ${OWNER}.${OWNER} ${SVRROOT}

# install the Ghidra server as a service
sudo ./svrInstall

# add the three example users
sudo ${SVRROOT}/server/svrAdmin -add user1
sudo ${SVRROOT}/server/svrAdmin -add user2
sudo ${SVRROOT}/server/svrAdmin -add user3

# return to the initial directory
popd
