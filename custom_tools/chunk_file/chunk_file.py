import os
import sys

if len(sys.argv) <= 1:
	this_file = os.path.basename(__file__)
	print("\nUsage:\t{} <name of file to split> <output filename>\n".format(this_file))
	sys.exit(1)

# Get commandline argument for filename
filename = sys.argv[1].strip()

# Get commandline argument for output filename
out_filename = sys.argv[2].strip()

print("Processing %s" % filename)

# Get the size of the file
file_size = os.path.getsize(filename)

print("File size is %s bytes" % file_size)

# Determine Chunksize.  Take into account odd file sizes
CHUNK_SIZE = file_size//2 
CHUNK_SIZE_R = file_size%2 

print("Chunk Size: %s bytes" % CHUNK_SIZE)
print("Chunk Size Remainder: %s bytes" % CHUNK_SIZE_R)

# Starting output number
file_number = 1

# Split the file
with open(filename, 'rb') as f:

	chunk = f.read(CHUNK_SIZE + CHUNK_SIZE_R)

	while chunk:
		with open(out_filename + '_part_' + str(file_number), 'wb') as chunk_file:
			chunk_file.write(chunk)
		file_number += 1
		chunk = f.read(CHUNK_SIZE)
