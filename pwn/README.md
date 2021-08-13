# BUUCTF

### python3 问题解决
因为python3上对字符串相加的情况做了一些新的限制，TypeError: must be str, not bytes
p64().decode("iso-8859-1")  对其进行iso-8859-1的编码即可
