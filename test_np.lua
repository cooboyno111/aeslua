require("aeslua");

sb = "12341234123412341234";
--sb = "12341234123412341234123412341234";
print(sb);
print(string.len(sb));
local ss=aeslua.fillpad(sb,'\t');
print(ss);
aa = aeslua.encrypt_np("password",ss);
print(aa);
print(string.len(aa));
bb = aeslua.decrypt_np("password",aa);
cc = aeslua.strippad(bb,'\t');
print(cc);
print(string.len(cc));
