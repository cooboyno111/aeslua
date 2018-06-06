local private = {};
local public = {};
aeslua = public;

local ciphermode = require("aeslua.ciphermode");
local util = require("aeslua.util");

--
-- Simple API for encrypting strings.
--

public.AES128 = 16;
public.AES192 = 24;
public.AES256 = 32;

public.ECBMODE = 1;
public.CBCMODE = 2;
public.OFBMODE = 3;
public.CFBMODE = 4;

function private.pwToKey(password, keyLength)
    local padLength = keyLength;
    if (keyLength == public.AES192) then
        padLength = 32;
    end
    
    if (padLength > #password) then
        local postfix = "";
        for i = 1,padLength - #password do
            postfix = postfix .. string.char(0);
        end
        password = password .. postfix;
    else
        password = string.sub(password, 1, padLength);
    end
    
    local pwBytes = {string.byte(password,1,#password)};
    password = ciphermode.encryptString(pwBytes, password, ciphermode.encryptCBC);
    
   -- password = string.sub(password, 1, keyLength);
   
    --print("pwd-len="..string.len(password))
    return {string.byte(password,1,#password)};
end

function public.fillpad(key,t)
local len=string.len(key);
local tkey=string.sub(key, 0,len)
local tfilllen=(math.floor(len/16))*16
--print(tfilllen);
local filllen=0;
if(len%16~=0)
then filllen=tfilllen+16;
end
--print(filllen);
for i = 1 , filllen-len , 1 do  
        tkey=tkey..t
end
--print(tkey);
return tkey;
end

function public.strippad(str,t)
local len=string.len(str);
--print(t:byte(1,2));
local index=0;
for i= len, 1,-1 do
   if str:byte(i,i+1)~=t:byte(1,2) then
         --print(i.."-"..str:byte(i,i+1))
         index=i;
         break
   end
end
local some=string.sub(str, 1, index)
--print(some);
return some;
end
--
-- Encrypts string data with password password.
-- password  - the encryption key is generated from this string
-- data      - string to encrypt (must not be too large)
-- keyLength - length of aes key: 128(default), 192 or 256 Bit
-- mode      - mode of encryption: ecb, cbc(default), ofb, cfb 
--
-- mode and keyLength must be the same for encryption and decryption.
--
function public.encrypt(password, data, keyLength, mode)
	assert(password ~= nil, "Empty password.");
	assert(password ~= nil, "Empty data.");
	 
    local mode = mode or public.CBCMODE;
    local keyLength = keyLength or public.AES128;

    local key = private.pwToKey(password, keyLength);
    local paddedData = util.padByteString(data);
    
    if (mode == public.ECBMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptECB);
    elseif (mode == public.CBCMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptCBC);
    elseif (mode == public.OFBMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptOFB);
    elseif (mode == public.CFBMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptCFB);
    else
        return nil;
    end
end

function public.encrypt_np(password, data, keyLength, mode)
	assert(password ~= nil, "Empty password.");
	assert(password ~= nil, "Empty data.");
	 
    local mode = mode or public.CBCMODE;
    local keyLength = keyLength or public.AES128;

    local key = private.pwToKey(password, keyLength);
    local paddedData;
    paddedData=public.fillpad(data,' ');
    if (mode == public.ECBMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptECB);
    elseif (mode == public.CBCMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptCBC);
    elseif (mode == public.OFBMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptOFB);
    elseif (mode == public.CFBMODE) then
        return ciphermode.encryptString(key, paddedData, ciphermode.encryptCFB);
    else
        return nil;
    end
end


--
-- Decrypts string data with password password.
-- password  - the decryption key is generated from this string
-- data      - string to encrypt
-- keyLength - length of aes key: 128(default), 192 or 256 Bit
-- mode      - mode of decryption: ecb, cbc(default), ofb, cfb 
--
-- mode and keyLength must be the same for encryption and decryption.
--
function public.decrypt(password, data, keyLength, mode)
    local mode = mode or public.CBCMODE;
    local keyLength = keyLength or public.AES128;

    local key = private.pwToKey(password, keyLength);
    
    local plain;
    if (mode == public.ECBMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptECB);
    elseif (mode == public.CBCMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptCBC);
    elseif (mode == public.OFBMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptOFB);
    elseif (mode == public.CFBMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptCFB);
    end
    result = util.unpadByteString(plain);
    if (result == nil) then
        return nil;
    end
    
    return result;
end

function public.decrypt_np(password, data, keyLength, mode)
    local mode = mode or public.CBCMODE;
    local keyLength = keyLength or public.AES128;

    local key = private.pwToKey(password, keyLength);
    
    local plain;
    if (mode == public.ECBMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptECB);
    elseif (mode == public.CBCMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptCBC);
    elseif (mode == public.OFBMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptOFB);
    elseif (mode == public.CFBMODE) then
        plain = ciphermode.decryptString(key, data, ciphermode.decryptCFB);
    end
    result = public.strippad(plain,' ');
    if (result == nil) then
        return nil;
    end
    
    return result;
end
