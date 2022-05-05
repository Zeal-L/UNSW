
def covert_bytes_to_GB(bytes_num):
    return round(bytes_num/1024/1024/1024,2)

def covert_bytes_to_K(bytes_num):
    return round(bytes_num/1024,2)

block_size = int(input("Please input the block size: "))
block_number = int(input("Please input the byte of block number: "))
direct = int(input("Please input the direct size: "))

single_indirect = direct + (block_size/block_number)
double_indirect = single_indirect + (block_size/block_number)**2
triple_indirect = double_indirect + (block_size/block_number)**3

print(f"\n\ndirect size: {direct*block_size}, {covert_bytes_to_K(direct*block_size)}K, {covert_bytes_to_GB(direct*block_size)}GB | 写入最坏 1w, 读取最坏1r")
print(f"single indirect size: {single_indirect*block_size}, {covert_bytes_to_K(single_indirect*block_size)}K, {covert_bytes_to_GB(single_indirect*block_size)}GB | 写入最坏 2w, 读取最坏2r")
print(f"double indirect size: {double_indirect*block_size}, {covert_bytes_to_K(double_indirect*block_size)}K, {covert_bytes_to_GB(double_indirect*block_size)}GB | 写入最坏 2r/1w 或者 3w, 读取最坏3r")
print(f"triple indirect size: {triple_indirect*block_size}, {covert_bytes_to_K(triple_indirect*block_size)}K, {covert_bytes_to_GB(triple_indirect*block_size)}GB | 写入最坏 4r/1w 或者 4w, 读取最坏4r")
