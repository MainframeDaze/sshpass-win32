#pragma once

// Holds the ANSI password and its length 
struct SecretBuffer {
	char* data;
	size_t len;
};

// Get the password (secret) from CredManager using <tag>
SecretBuffer get_vault_pass(const char* tag);

// Zero out and free the SecretBuffer
void final_burn(SecretBuffer& s);