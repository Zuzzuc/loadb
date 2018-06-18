#!/bin/bash

# This program is used to load loadb encoded bash scripts. 

# This acts as both a decoder and a encoder, the default mode is decode.


#
# 0: encrypted. Will use inline key by default, but supports setting a custom key.
# 1: no encryption. Only stores a compressed b64.
#
##

# loadb encrypted by default using a randomly generated key on execution stored in string, unless a custom key is supplied.
# This key is included as $key IF no custom encryption is chosen.


# Default variables
loadb_m="decode"
mode="print"
payload=""
key=""
keylength="0"
out=""


# For encoding modes are: 0 or 'encrypt' and 1 or 'store' (Default is 0. A random string will be generated as key and stored in key data)

# Argument handler

if [ "$*" != "" ];then	
	for i in "$@";do					
		case "$i" in		
		"$0")
    		continue
    		;;
   		-mode=*)
   			mode="${i#*=}"
   			;;
   		-encode)
   			loadb_m="encode"
   			;;
   		-decode)
   			loadb_m="decode"
   			;;
   		-file=*)
   			c="${i#*=}" && c="${c/\\/}" && file="${c%${c##*[![:space:]]}}"
   			if [ ! -f "$file" ];then
   				echo "File '$file' does not exist."
   				exit 2
   			fi
   			;;
   		-payload=*)
   			payload="${i#*=}"
   			;;
   		-key=*)
   			key="${i#*=}"
   			;;
   		-keylength=*)
   			# Used to set the length of the auto-generated key in encode.
   			keylength="${i#*=}"
   			;;
   		-out=*)
   			c="${i#*=}" && c="${c/\\/}"
   			out="${c%${c##*[![:space:]]}}"
   			;;
   		*)
   			echo "Unknown argument encountered. Unknown argument: $i"
   			;;
		esac
	done
fi

# Safety checks
if [ "$loadb_m" == "decode" ];then
	if [ "$mode" != "host" ] && [ "$mode" != "parent" ] && [ "$mode" != "launchd" ] && [ "$mode" != "print" ];then
		echo "Specified mode is not supported. Mode submitted: $mode"
		exit 1
	fi
elif [ "$loadb_m" == "encode" ];then
	if [ "$mode" != "0" ] && [ "$mode" != "1" ];then
		echo "Specified mode is not supported. Mode submitted: $mode"
		exit 1
	fi
fi

if [ "$loadb_m" == "decode" ];then
	
	# Verify format
	
	if [ "$payload" == "" ];then
		# We can read the file to memory since it should not contain any null bytes
		payload="$(cat "$file")"
	fi
	
	# Begin verification
	if [[ $payload =~ ^[0-9][0-9]*x[0-9][0-9]*x.*$ ]];then
		# Ensure keylength is int
		c="${payload#[0-9]*x}"
		if ! [[ "${c%%x*}" =~ ^[0-9][0-9]*$ ]];then
			echo "FORMAT ERROR"
			exit 3
		fi
	else
		# Fail. Format is incorrect.
		echo "FORMAT ERROR"
		exit 3
	fi
	
	# Begin decoding
	
	# Go through all possible modes and choose the one bound to the current loadb encoding.
	if [ "${payload//x*}" == "0" ];then
		# loadb string is encrypted. Begin decryption
						
		# Assign key.
		if [ "$key" == "" ];then
			# Get length
			c="${payload#[0-9]*x}" && keylength="${c//x*}"
			
			# Get key
			c="${payload#[0-9]*x[0-9]*x}" && key="${c::$keylength}"
		else
			# Custom key submitted, set keylength.
			keylength="${#key}"
		fi
		
		# Remove key info from string so only the data part of loadb file remains
		data="${payload#[0-9]*x[0-9]*x}" && data="${data:$keylength-${#data}}"
		
		# Decode
		if [ "$out" == "" ];then
			echo "$data" | base64 -D | gzip -d | openssl aes-256-cbc -a -d -pass pass:"$key"
		else
			echo "$data" | base64 -D | gzip -d | openssl aes-256-cbc -a -d -pass pass:"$key" > "$out"
		fi
	elif [ "${payload//x*}" == "1" ];then
		# loadb string is not encrypted. Just decompress it.
		
		# Remove key data from string so only the data part of loadb file remains
		data="${payload#[0-9]*x[0-9]*x}" && data="${data:$keylength-${#data}}"
		
		# Decode
		if [ "$out" == "" ];then
			echo "$data"| base64 -D | gzip -d
		else
			echo "$data"| base64 -D | gzip -d > "$out"
		fi
	
	else
		echo "Wrong mode in format!"
		exit 3
	fi
	
elif [ "$loadb_m" == "encode" ];then
	# This is used to generate loadb encrypted strings. 
	
	# Decide if we are going to read from file or from stdin
	if [ "$payload" == "" ];then
		if [ "$file" == "" ];then
			echo "No input!"
			exit 3
		else
			if [ ! -f "$file" ];then
				echo "Input file '$file' does not exist"
				exit 3
			fi
		fi	
	fi
	
	# Begin encoding
	if [ "$mode" == "0" ] || [ "$mode" == "encrypt" ];then
		# Mode 0 is encrypt. Look if we got assigned a key, if not generate a secure one.
	
		# Set key
		if [ "$key" == "" ];then
			# Generate key
			if [ "$keylength" == "0" ];then
				keylength="32"
			fi
			key="$(head -c "$keylength" "/dev/urandom" | base64 | head -c "$keylength")"
		else
			keylength="${#key}"
		fi
		
		## Encode content
		# Encode data
		
		
		
		# Decide if we are going to read from file or from stdin
		if [ "$payload" == "" ];then
			if [ -f "$file" ];then
				# If file does exist. Read it to payload to encode.
				data="$(openssl aes-256-cbc -a -in "$file" -pass pass:"$key" | gzip -9 | base64)"
			fi	
		else
			data="$(echo "$payload" | openssl aes-256-cbc -a -pass pass:"$key" | gzip -9 | base64)"
		fi
		
		# Merge mode, keydata and data into the loadb string.
		loadb_s="$mode\0x$keylength\0x$key$data"
				
		# Return the loadb string
		if [ "$out" == "" ];then
			echo -ne "$loadb_s"
		else
			echo -ne "$loadb_s" > "$out"
		fi
		
	elif [ "$mode" == "1" ] || [ "$mode" == "store" ];then
		# Mode is store. Just compress and b64
		
		if [ "$key" != "" ];then
			echo "Key sumbitted to encode store. Store will not encrypt the content, use encode encrypt for that."
			exit 10
		fi
	
		## Encode content
		# Encode data
		data="$(echo "$payload" | gzip -9 | base64)"
	
		# Merge mode, keydata and data into the loadb string.
		loadb_s="$mode\0x$keylength\0x$key$data"
		
		# Return the loadb string
		if [ "$out" == "" ];then
			echo -ne "$loadb_s"
		else
			echo -ne "$loadb_s" > "$out"
		fi
	fi
fi