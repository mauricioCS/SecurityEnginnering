/*
 * EML RSA - Alternative RSA implementation.
 * 
 * Authors:
 * Eduardo Garcia Misiuk <eduardogmisiuk@gmail.com>
 * Mauricio Caetano Silva <mauriciocaetanosilva@gmail.com>
 * Lucas Yudi Sugi <lucas.sugi@usp.br>
 */

/*
 	This file is part of EML RSA.

	EML RSA is free software: you can redistribute it and/or modify
	it under the terms of the GNU General Public License as published by
	the Free Software Foundation, either version 3 of the License, or
	(at your option) any later version.

	EML RSA is distributed in the hope that it will be useful,
	but WITHOUT ANY WARRANTY; without even the implied warranty of
	MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
	GNU General Public License for more details.

	You should have received a copy of the GNU General Public License
	along with EML RSA. If not, see <http://www.gnu.org/licenses/>.
*/

#ifndef _EML_RSA_H_
#define _EML_RSA_H_

#include <string>

/* 
 * Decrypts the message at the file message_fn, using the key at key_fn and
 * put the decrypted message at the file encrypted_message_fn.
 */
void decrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn);

/* 
 * Encrypts the message at the file encrypted_message_fn, using the key at key_fn and
 * put the encrypted message at the file message_fn.
 */
void encrypt (std::string &key_fn, std::string &message_fn, std::string &encrypted_message_fn);

/*
 * Create the public and private keys to be used in the algorithm and saves it
 * in separate files "key_fn.pub", "key_fn.prv".
 */
void generate_keys (unsigned long int seed, std::string &key_fn);

#endif // _EML_RSA_H_
