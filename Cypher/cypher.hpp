#define BLOCK_SIZE 32

typedef  unsigned char byte;

namespace cypher
{
	// init matrix used to construct the new block key
	inline byte i_vec[32]
	{
		0x08,0x29,0x04,0x34,0x40,
		0x1f,0x3d,0x2b,0x2d,0x53,
		0x0e,0x2c,0x3d,0x4c,0x2f,
		0x38,0x1b,0x0e,0x31,0x36,
		0x61,0x46,0x11,0x4d,0x25,
		0x3c,0x25,0x41,0x43,0x1e,
		0x38,0x48
	};

	// generate a new 32 byte key from the old block
	void calc_next_block_key(byte* block_data, byte* key, int block, byte* iv, byte* new_key)
	{
		byte temp[BLOCK_SIZE];
		for (int i = 0; i < BLOCK_SIZE; i++)
		{
			byte blk_byte = (byte) (block & 0xFF);
			temp[i] = (byte) (key[i] ^ block_data[i] ^ iv[i] ^ blk_byte);

			temp[i] = (byte) ((temp[i] * (i + 1)) ^ (temp[i] >> 3));
		}

		const int rounds = key[block_data[0] % BLOCK_SIZE];
		for (int r = 0; r < rounds; r++)
		{
			byte round_temp[BLOCK_SIZE];
			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				int rotated_idx = (i + (r + 1)) % BLOCK_SIZE;
				round_temp[i] = (byte) (temp[i] ^ temp[rotated_idx] ^ (byte) ((r + 1) * 0x69));
			}

			for (int i = 0; i < BLOCK_SIZE; i++)
				temp[i] = round_temp[i];
		}

		for (int i = 0; i < BLOCK_SIZE; i++)
			new_key[i] = temp[i];
	}

	// generate a new secure key and init the iv matrix
	byte* generate_key(byte* data, int data_size, byte* iv)
	{
		byte state[BLOCK_SIZE];
		for (int i = 0; i < BLOCK_SIZE; i++)
			state[i] = i_vec[i];

		// Fold data into state
		for (int i = 0; i < data_size; i++)
		{
			int pos = i % BLOCK_SIZE;
			state[pos] = (byte) (state[pos] ^ data[i] ^ (byte) (i * 0x5A));
		}

		const int rounds = 8;
		for (int r = 0; r < rounds; r++)
		{
			byte temp[BLOCK_SIZE];
			for (int i = 0; i < BLOCK_SIZE; i++)
			{
				int next_idx = (i + r + 1) % BLOCK_SIZE;
				byte val = (byte) (state[i] ^ state[next_idx] ^ (byte) ((r + 1) * 0xA5));
				byte rotated = (byte) ((val >> ((r + 1) & 7)) | (val << (8 - ((r + 1) & 7))));
				byte mixed = (byte) (rotated ^ (rotated >> 3) ^ (rotated * (i + 1)));
				temp[i] = mixed;
			}
			for (int i = 0; i < BLOCK_SIZE; i++)
				state[i] = temp[i];
		}

		byte* key = new byte[BLOCK_SIZE];
		for (int i = 0; i < BLOCK_SIZE; i++)
			key[i] = state[i];

		byte iv_state[BLOCK_SIZE];
		for (int i = 0; i < BLOCK_SIZE; i++)
		{
			int idx = (i + 13) % BLOCK_SIZE;
			iv_state[i] = (byte) (state[i] ^ cypher::i_vec[idx] ^ (byte) ((i + 1) * 0x3F));
		}

		for (int i = 0; i < BLOCK_SIZE; i++)
			iv[i] = iv_state[i];

		return key;
	}

	// encrypt / decrypt the data, initial_key parameter will return the 32byte key used for the operation
	byte* encdec(byte* data, int data_size, byte* initial_key, byte* iv, bool dec)
	{
		// generate a new key and fill iv
		byte* key = initial_key;
		if (!dec)
		{
			byte* key = generate_key(data, data_size, iv);
			initial_key = key;
		}

		// add padding to align block with BLOCK_SIZE
		int new_data_size = (data_size + BLOCK_SIZE - 1) / BLOCK_SIZE * BLOCK_SIZE;
		byte* padded_data = new byte[new_data_size];

		// copy data
		for (int i = 0; i < data_size; i++)
			padded_data[i] = data[i];

		// zero out remaining bytes
		for (int i = data_size; i < new_data_size; i++)
			padded_data[i] = 0;

		byte* encrypted_data = new byte[new_data_size];
		byte new_key[BLOCK_SIZE]; 

		int runs = 0;
		while (runs * BLOCK_SIZE != new_data_size)
		{
			for (int i = runs * BLOCK_SIZE; i < (runs + 1) * BLOCK_SIZE; i++)
				encrypted_data[i] = padded_data[i] ^ key[i % 32];

			byte* block_data = new byte[BLOCK_SIZE];
			for (int i = 0; i < BLOCK_SIZE; i++)
				block_data[i] = encrypted_data[i + (runs * BLOCK_SIZE)];

			calc_next_block_key(block_data, key, runs, iv, new_key);
			key = new_key;

			delete[] block_data;
			runs++;
		}

		delete[] padded_data;

		// zero out padded bytes that would expose the key
		for (int i = data_size; i < new_data_size; i++)
			encrypted_data[i] = 0;

		return encrypted_data;
	}
}