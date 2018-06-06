require("aeslua");
sb = "12341234123412341234";
--sb = "12341234123412341234123412341234";
print(sb);
print(string.len(sb));
local ss=aeslua.fillpad(sb,'\t');
aeslua.printstrbyte("ss",ss);
print(ss);
aa = aeslua.encrypt_np("password",ss);
aeslua.printstrbyte("aa",aa);
print(aa);
print(string.len(aa));
bb = aeslua.decrypt_np("password",aa);
print("bb len="..string.len(bb))
aeslua.printstrbyte("bb",bb);
cc = aeslua.strippad(bb,'\t');
print(cc);
print(string.len(cc));
