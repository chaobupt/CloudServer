#define _CRT_SECURE_NO_WARNINGS
#define _CRT_NONSTDC_NO_DEPRECATE

#include "seal/seal.h"
#include <stdio.h>
#include <string.h>
#include <fstream>
#include <iomanip>
#include <Winsock2.h>
#include <process.h>
#include "zip.h"
#include "unzip.h"
#include "base64.h"
#include <iostream>

using namespace seal;
using namespace std;

/******************************************压缩解压缩函数**************************************************/

void unzip(const TCHAR* filePath) {
	//解压photo.zip
	cout << "开始解压缩" << endl;
	HZIP hz = OpenZip(filePath, 0);
	char *unzipPath = "\\photo0";
	SetUnzipBaseDir(hz, unzipPath);

	ZIPENTRY ze;
	GetZipItem(hz, -1, &ze);
	int numitems = ze.index;
	for (int zi = 0; zi < numitems; zi++)
	{
		ZIPENTRY ze;
		GetZipItem(hz, zi, &ze);
		UnzipItem(hz, zi, ze.name);
	}
	CloseZip(hz);
	cout << "完成解压缩" << endl;
}


/******************************************Seal CKKS相关函数**************************************************/

static string loadCipherFromFile(shared_ptr<SEALContext> context, const string &filePath, Ciphertext &ciphertext)
{
	ifstream file(filePath, ios_base::binary);
	string cipherString = "";
	string cipherStringEncoded = "";
	if (file.is_open())
	{
		stringstream ss;
		ss << file.rdbuf();
		cipherStringEncoded = ss.str();
		cipherString = base64_decode(ss.str());
		ss.str(cipherString);
		ciphertext.unsafe_load(context, ss);
	}
	return cipherString;
}

template <typename T>
static string loadFromFile(shared_ptr<SEALContext> context, const string &filePath, T &key)
{
	ifstream file(filePath, ios_base::binary);
	string keyString = "";
	string keyStringEncoded = "";
	if (file.is_open())
	{
		stringstream ss;
		ss << file.rdbuf();
		keyStringEncoded = ss.str();
		keyString = base64_decode(ss.str());
		ss.str(keyString);
		key.unsafe_load(context, ss);
	}
	return keyStringEncoded;
}

template <typename T>
static string encodeSealToBase64(const T &object)
{
	ostringstream ss;
	object.save(ss);
	return base64_encode(ss.str());
}

template <typename T>
static void saveToFile(const string &filePath, T &key)
{
	string keyString = encodeSealToBase64(key);
	ofstream saveFile(filePath, ios_base::binary);
	saveFile.write(keyString.c_str(), keyString.size());
}

/**********************************************打印函数********************************************************/

/*
Helper function: Prints the name of the example in a fancy banner.
*/
inline void print_example_banner(std::string title)
{
	if (!title.empty())
	{
		std::size_t title_length = title.length();
		std::size_t banner_length = title_length + 2 * 10;
		std::string banner_top = "+" + std::string(banner_length - 2, '-') + "+";
		std::string banner_middle =
			"|" + std::string(9, ' ') + title + std::string(9, ' ') + "|";

		std::cout << std::endl
			<< banner_top << std::endl
			<< banner_middle << std::endl
			<< banner_top << std::endl;
	}
}

/*
Helper function: Prints the parameters in a SEALContext.
*/
inline void print_parameters(std::shared_ptr<seal::SEALContext> context)
{
	// Verify parameters
	if (!context)
	{
		throw std::invalid_argument("context is not set");
	}
	auto &context_data = *context->key_context_data();

	/*
	Which scheme are we using?
	*/
	std::string scheme_name;
	switch (context_data.parms().scheme())
	{
	case seal::scheme_type::BFV:
		scheme_name = "BFV";
		break;
	case seal::scheme_type::CKKS:
		scheme_name = "CKKS";
		break;
	default:
		throw std::invalid_argument("unsupported scheme");
	}
	std::cout << "/" << std::endl;
	std::cout << "| Encryption parameters :" << std::endl;
	std::cout << "|   scheme: " << scheme_name << std::endl;
	std::cout << "|   poly_modulus_degree: " <<
		context_data.parms().poly_modulus_degree() << std::endl;

	/*
	Print the size of the true (product) coefficient modulus.
	*/
	std::cout << "|   coeff_modulus size: ";
	std::cout << context_data.total_coeff_modulus_bit_count() << " (";
	auto coeff_modulus = context_data.parms().coeff_modulus();
	std::size_t coeff_mod_count = coeff_modulus.size();
	for (std::size_t i = 0; i < coeff_mod_count - 1; i++)
	{
		std::cout << coeff_modulus[i].bit_count() << " + ";
	}
	std::cout << coeff_modulus.back().bit_count();
	std::cout << ") bits" << std::endl;

	/*
	For the BFV scheme print the plain_modulus parameter.
	*/
	if (context_data.parms().scheme() == seal::scheme_type::BFV)
	{
		std::cout << "|   plain_modulus: " << context_data.
			parms().plain_modulus().value() << std::endl;
	}

	std::cout << "\\" << std::endl;
}

/*
Helper function: Prints the `parms_id' to std::ostream.
*/
inline std::ostream &operator <<(std::ostream &stream, seal::parms_id_type parms_id)
{
	/*
	Save the formatting information for std::cout.
	*/
	std::ios old_fmt(nullptr);
	old_fmt.copyfmt(std::cout);

	stream << std::hex << std::setfill('0')
		<< std::setw(16) << parms_id[0] << " "
		<< std::setw(16) << parms_id[1] << " "
		<< std::setw(16) << parms_id[2] << " "
		<< std::setw(16) << parms_id[3] << " ";

	/*
	Restore the old std::cout formatting.
	*/
	std::cout.copyfmt(old_fmt);

	return stream;
}

/*
Helper function: Prints a vector of floating-point values.
*/
template<typename T>
inline void print_vector(std::vector<T> vec, std::size_t print_size = 4, int prec = 3)
{
	/*
	Save the formatting information for std::cout.
	*/
	std::ios old_fmt(nullptr);
	old_fmt.copyfmt(std::cout);

	std::size_t slot_count = vec.size();

	std::cout << std::fixed << std::setprecision(prec);
	std::cout << std::endl;
	if (slot_count <= 2 * print_size)
	{
		std::cout << "    [";
		for (std::size_t i = 0; i < slot_count; i++)
		{
			std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
		}
	}
	else
	{
		(vec.resize)((std::max)(vec.size(), 2 * print_size));
		std::cout << "    [";
		for (std::size_t i = 0; i < print_size; i++)
		{
			std::cout << " " << vec[i] << ",";
		}
		if (vec.size() > 2 * print_size)
		{
			std::cout << " ...,";
		}
		for (std::size_t i = slot_count - print_size; i < slot_count; i++)
		{
			std::cout << " " << vec[i] << ((i != slot_count - 1) ? "," : " ]\n");
		}
	}
	std::cout << std::endl;

	/*
	Restore the old std::cout formatting.
	*/
	std::cout.copyfmt(old_fmt);
}


/*
Helper function: Prints a matrix of values.
*/
template<typename T>
inline void print_matrix(std::vector<T> matrix, std::size_t row_size)
{
	/*
	We're not going to print every column of the matrix (there are 2048). Instead
	print this many slots from beginning and end of the matrix.
	*/
	std::size_t print_size = 5;

	std::cout << std::endl;
	std::cout << "    [";
	for (std::size_t i = 0; i < print_size; i++)
	{
		std::cout << std::setw(3) << std::right << matrix[i] << ",";
	}
	std::cout << std::setw(3) << " ...,";
	for (std::size_t i = row_size - print_size; i < row_size; i++)
	{
		std::cout << std::setw(3) << matrix[i]
			<< ((i != row_size - 1) ? "," : " ]\n");
	}
	std::cout << "    [";
	for (std::size_t i = row_size; i < row_size + print_size; i++)
	{
		std::cout << std::setw(3) << matrix[i] << ",";
	}
	std::cout << std::setw(3) << " ...,";
	for (std::size_t i = 2 * row_size - print_size; i < 2 * row_size; i++)
	{
		std::cout << std::setw(3) << matrix[i]
			<< ((i != 2 * row_size - 1) ? "," : " ]\n");
	}
	std::cout << std::endl;
};

/*
Helper function: Print line number.
*/
inline void print_line(int line_number)
{
	std::cout << "Line " << std::setw(3) << line_number << " --> ";
}