#include "SEALWrapper.h"
#include <fstream>
#include <vector>

namespace Microsoft
{
	namespace Research
	{
		SEALWrapper::SEALWrapper(int slotCount)
		{
			m_slotCount = slotCount;
			int polyModulus = 2 * m_slotCount;

			// The coeff_modulus parameter below is secure up to polyModulus == 8192.
			if (polyModulus > 8192)
			{
				throw invalid_argument("insecure parameters");
			}

			// Create the seal environment
			EncryptionParameters parms(scheme_type::CKKS);
			parms.set_poly_modulus_degree(polyModulus);
			parms.set_coeff_modulus({
				0xffffffffffc0001, // 60 bits
				0x7fffffffffcc001, // 59 bits
				0x7fffffffffa4001, // 59 bits
				0xffffe80001       // 40 bits
				});

			auto context = SEALContext::Create(parms);
			m_evaluator = new Evaluator(context);
			m_encoder = new CKKSEncoder(context);

			EncryptionParameters data_parms = context->key_context_data()->parms();
			m_scale = static_cast<double>(data_parms.coeff_modulus().back().value());
			m_scale_small = pow(2.0, 25);
		}

		SEALWrapper::SEALWrapper(int slotCount, bool encryptionSetup, bool keySetup)
		{
			m_slotCount = slotCount;
			int polyModulus = 2 * m_slotCount;

			// The coeff_modulus parameter below is secure up to polyModulus == 8192.
			if (polyModulus > 8192)
			{
				throw invalid_argument("insecure parameters");
			}

			// Create the seal environment
			EncryptionParameters parms(scheme_type::CKKS);
			parms.set_poly_modulus_degree(polyModulus);
			parms.set_coeff_modulus({
				0xffffffffffc0001, // 60 bits
				0x7fffffffffcc001, // 59 bits
				0x7fffffffffa4001, // 59 bits
				0xffffe80001       // 40 bits
				});

			auto context = SEALContext::Create(parms);
			m_evaluator = new Evaluator(context);
			m_encoder = new CKKSEncoder(context);
			EncryptionParameters data_parms = context->key_context_data()->parms();
			m_scale = static_cast<double>(data_parms.coeff_modulus().back().value());
			m_scale_small = pow(2.0, 25);

			if (encryptionSetup)
			{
				KeyGenerator keygen(context);
				m_publicKey = new PublicKey(keygen.public_key());
				m_secretKey = new SecretKey(keygen.secret_key());
				m_encryptor = new Encryptor(context, keygen.public_key());
				m_decryptor = new Decryptor(context, keygen.secret_key());

				if (keySetup)
				{
					m_relinKeys = new RelinKeys(keygen.relin_keys());
				}
			}
		}

		SEALWrapper::~SEALWrapper()
		{
			// Delete the pointers if they exist
			if (m_evaluator) { delete m_evaluator; }
			if (m_encoder) { delete m_encoder; }
			if (m_encryptor) { delete m_encryptor; }
			if (m_decryptor) { delete m_decryptor; }

			if (m_publicKey) { delete m_publicKey; }
			if (m_secretKey) { delete m_secretKey; }
			if (m_relinKeys) { delete m_relinKeys; }

			if (m_addedCipherBase64) { delete m_addedCipherBase64; }
			if (m_statsCipherBase64) { delete m_statsCipherBase64; }
			if (m_summaryCipherBase64) { delete m_summaryCipherBase64; }
		}

		void SEALWrapper::LoadKeys(String^ galKeys, String^ galKeysSingleStep, String^ relinKeys)
		{
			// Convert to std::string
			marshal_context marshalContext;
			string galString = marshalContext.marshal_as<std::string>(galKeys);
			string galSingleStepString = marshalContext.marshal_as<std::string>(galKeysSingleStep);
			string relinString = marshalContext.marshal_as<std::string>(relinKeys);

			// Free the memory if already set
			if (m_relinKeys) { free(m_relinKeys); }

			// Make new instances of the keys
			m_relinKeys = new RelinKeys();

			// Load the keys
			ToSealObject<RelinKeys>(relinString, *m_relinKeys, true);
		}

		String^ SEALWrapper::Encrypt(List<double>^ values)
		{
			// Convert the List to a vector
			vector<double> input;
			for (int i = 0; i < values->Count; i++)
			{
				input.push_back(values[i]);
			}

			// Encrypt
			Plaintext plain;
			m_encoder->encode(input, m_scale, plain);
			Ciphertext encrypted;
			m_encryptor->encrypt(plain, encrypted);

			// Convert to base64 and return
			string cipherBase64 = FromSealObject<Ciphertext>(encrypted, true);
			return gcnew String(cipherBase64.c_str());
		}

		List<double>^ SEALWrapper::Decrypt(String ^str)
		{
			// Convert to std::string
			marshal_context marshalContext;
			string cipherBase64 = marshalContext.marshal_as<std::string>(str);

			// Load the cipher
			Ciphertext ciphertext;
			ToSealObject<Ciphertext>(cipherBase64, ciphertext, true);

			// Decrypt
			Plaintext plaintext;
			m_decryptor->decrypt(ciphertext, plaintext);
			vector<double> result;
			m_encoder->decode(plaintext, result);

			// Covert to List and return
			List<double>^ resultList = gcnew List<double>((int)result.size());
			for (int i = 0; i < (int)result.size(); i++)
			{
				resultList->Add(result[i]);
			}
			return resultList;
		}

		bool SEALWrapper::AddCiphers(String^ CipherStr1, String^ CipherStr2)
		{
			// Convert to std::string
			msclr::interop::marshal_context marshalContext;
			std::string cipherStr1 = marshalContext.marshal_as<std::string>(CipherStr1);
			std::string cipherStr2 = marshalContext.marshal_as<std::string>(CipherStr2);

			// Convert the base64 strings to Ciphers
			Ciphertext Cipher1, Cipher2;
			ToSealObject<Ciphertext>(cipherStr1, Cipher1, true);
			ToSealObject<Ciphertext>(cipherStr2, Cipher2, true);

			// Make sure the input is the right format
			if (((int)Cipher1.poly_modulus_degree() != m_slotCount * 2) ||
				((int)Cipher1.poly_modulus_degree() != (int)Cipher2.poly_modulus_degree()))
			{
				return false;
			}

			// Add the ciphertexts
			Ciphertext resultCipher;
			m_evaluator->add(Cipher1, Cipher2, resultCipher);

			// Set the base64 result and return true
			m_addedCipherBase64 = new string(FromSealObject<Ciphertext>(resultCipher, true));
			return true;
		}

		template<class T>
		void SEALWrapper::ToSealObject(string input, T &output, bool base64)
		{
			if (base64)
			{
				input = base64_decode(input);
			}
			stringstream stream(input);
			output.unsafe_load(stream);
		}

		template<class T>
		string SEALWrapper::FromSealObject(T input, bool base64)
		{
			stringstream stream;
			input.save(stream);
			string encryptedString = stream.str();
			if (base64)
			{
				encryptedString = base64_encode(reinterpret_cast<const uint8_t*>(encryptedString.c_str()), encryptedString.size());
			}
			return encryptedString;
		}
	}
}
