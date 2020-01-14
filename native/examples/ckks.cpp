// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"
#include "CryptoContext.h"

using namespace std;
using namespace seal;

void example_ckks()
{
	print_example_banner("Example: CKKS Basics");

	EncryptionParameters parms(scheme_type::CKKS);

	/*
	We saw in `2_encoders.cpp' that multiplication in CKKS causes scales           CKKS�еĳ˷�����������е�scales������ �κ����ĵ�scaleһ�����ܽӽ�coeff_modulus ������size,
	in ciphertexts to grow. The scale of any ciphertext must not get too close		�������ľͻ�ľ��ռ����洢�Ŵ�����ġ�
	to the total size of coeff_modulus, or else the ciphertext simply runs out of
	room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
	functionality that can reduce the scale, and stabilize the scale expansion.		CKKS�����ṩ��һ����rescale�����ܣ����Լ���scale�����ȶ�scale��չ��

	Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').		rescale��һ��ģ��ת������(����һ��' 3_levels.cpp')����ת��ģ��ʱ�������coeff_modulo���Ƴ���
	As modulus switching, it removes the last of the primes from coeff_modulus,		��һ������������Ϊ�����ã�����ͨ���Ƴ���������С���ĵķ�Χ��ͨ����������Ҫ��scale��α仯�������Ŀ��ƣ�
	but as a side-effect it scales down the ciphertext by the removed prime.		�����Ϊʲô��CKKS�����У�Ϊcoeff_modulsʹ�þ�����ѡ��������Ϊ����
	Usually we want to have perfect control over how the scales are changed,
	which is why for the CKKS scheme it is more common to use carefully selected
	primes for the coeff_modulus.

	More precisely, suppose that the scale in a CKKS ciphertext is S, and the		����ȷ��˵������CKKS�����е�scale��S�����ҵ�ǰ��coeff_modulus(��������)�е����һ��������P��
	last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling	rescaling��������һ�㽫scale����ΪS/P����������P��coeff_modulus���Ƴ�����ģ���л��е�ͨ������һ����
	to the next level changes the scale to S/P, and removes the prime P from the	����������������rescaling�Ĵ������Ӷ������˼���ĳ˷���ȡ�
	coeff_modulus, as usual in modulus switching. The number of primes limits
	how many rescalings can be done, and thus limits the multiplicative depth of
	the computation.

	It is possible to choose the initial scale freely. One good strategy can be		��coeff_modul_be�����ó�ʼscale S������P_iΪ�˴˷ǳ��ӽ�
	to is to set the initial scale S and primes P_i in the coeff_modulus to be		��������ڳ˷�֮ǰ��S scale���˷�֮����S^2��Rescaling ֮����S^2/P_i��
	very close to each other. If ciphertexts have scale S before multiplication,
	they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
	P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the �������Ǿ��ȶ������������������ʹ��scale�ӽ�S
	scales to be close to S throughout the computation. Generally, for a circuit		һ����˵���������D�ĵ�·��������ҪRescale D������������Ҫ������D��ϵ��ģ����ȥ����
	of depth D, we need to rescale D times, i.e., we need to be able to remove D
	primes from the coefficient modulus. Once we have only one prime left in the    һ����coeff_modules��ֻʣ��һ��������ʣ�µ����������S�󼸸�λ���Ա������ĵ�С����ǰֵ��
	coeff_modulus, the remaining prime must be larger than S by a few bits to
	preserve the pre-decimal-point value of the plaintext.

	Therefore, a generally good strategy is to choose parameters for the CKKS
	scheme as follows:

		(1) Choose a 60-bit prime as the first prime in coeff_modulus. This will    ѡ��һ��60λ������Ϊcoeff_modules�еĵ�һ���������⽫����ʱ�ṩ��߾���;
			give the highest precision when decrypting;
		(2) Choose another 60-bit prime as the last element of coeff_modulus, as    ѡ����һ��60λ������Ϊcoeff_modules�����һ��Ԫ�أ��⽫���������������
			this will be used as the special prime and should be as large as the
			largest of the other primes;
		(3) Choose the intermediate primes to be close to each other.				ѡ����м��������

	We use CoeffModulus::Create to generate primes of the appropriate size. Note    coeff_modulus �ܹ�200bits, ��������ǵ�poly_modulus_degree: coeff_modulus_degree::MaxBitCount(8192)����218
	that our coeff_modulus is 200 bits total, which is below the bound for our
	poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.
	*/

	size_t poly_modulus_degree = 8192; //degree of polynomial modulus ����ʽģ����
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40})); //([ciphertext] coefficient modulus);(����)ģ��ϵ��

	auto context = SEALContext::Create(parms);
	print_parameters(context);
	cout << endl;

	KeyGenerator keygen(context);
	auto public_key = keygen.public_key();
	auto secret_key = keygen.secret_key();
	auto relin_keys = keygen.relin_keys();		//relinearize
	Encryptor encryptor(context, public_key);
	Evaluator evaluator(context);				//performs computations on encrypted data and relinearizes encrypted data after multiplication operations
	Decryptor decryptor(context, secret_key);

	CKKSEncoder encoder(context);				//encodes integers as plaintext polynomials and decodes plaintext polnomials as integers
	size_t slot_count = encoder.slot_count();
	cout << "Number of slots: " << slot_count << endl; // In CKKS the number of slots is poly_modulus_degree / 2 and each slot encodes one real or complex number.

	vector<double> input1{0.04891288, 0.031262737, 0.030423492, 0.0616257 };
	cout << "Input vector1: " << endl;
	print_vector(input1,4,9); //����ΪС�����9λ

	vector<double> input2{0.020476542, -0.08371191, -0.038826868, 6.062781E-4 };
	cout << "Input vector2: " << endl;

	print_vector(input2,4,9); //����ΪС�����9λ

	/*********************************************************���㣨x1-x2��^2********************************************************************************************/
	cout << "Start Evaluating polynomial (x1-x2)^2 ..." << endl;

	Plaintext x1_plain, x2_plain;
	double scale = pow(2.0, 40);			//������뾫�ȵ�scale����
	print_line(__LINE__);
	cout << "Encode input vector1." << endl;
	encoder.encode(input1, scale, x1_plain);// Encodes a double-precision floating-point real number into a plaintext polynomial.
	encoder.encode(input2, scale, x2_plain);

	vector<double> x1_output, x2_output;
	cout << "    + Decode input vector ...... Correct." << endl;
	encoder.decode(x1_plain, x1_output);
	encoder.decode(x2_plain, x2_output);
	print_vector(x1_output,4,9);
	print_vector(x2_output,4,9);

	Ciphertext x1_encrypted, x2_encrypted;
	encryptor.encrypt(x1_plain, x1_encrypted);	//x1_plain---����--->x1_encrypted
	encryptor.encrypt(x2_plain, x2_encrypted);	//x2_plain---����--->x2_encrypted

	/*
		Next, we compute (x1-x2)^2.
   */
	print_line(__LINE__);
	cout << "Compute x1_minus_x2_sq ((x1-x2)^2) and relinearize." << endl;

	Ciphertext x1_minus_x2_sq;
	evaluator.sub(x1_encrypted,x2_encrypted,x1_minus_x2_sq);
	evaluator.square_inplace(x1_minus_x2_sq);
	cout << "    + size of x1_minus_x2_sq: " << x1_minus_x2_sq.size() << endl;
	evaluator.relinearize_inplace(x1_minus_x2_sq, relin_keys);
	cout << "    + Scale of (x1-x2)^2 before rescale: " << log2(x1_minus_x2_sq.scale())
		<< " bits" << endl;

	cout << "Decrypt and decode (x1-x2)^2." << endl;
	cout << "    + Expected result:" << endl;
	vector<double> true_result;
	
	for (size_t i = 0; i < slot_count; i++)
	{
		double x1 = input1[i];
		double x2 = input2[i];
		true_result.push_back((x1-x2)*(x1-x2));
	}
	print_vector(true_result, 4, 9);


	Plaintext decrypted_result;
	cout << "    + decryption of x1_minus_x2_sq: ";
	decryptor.decrypt(x1_minus_x2_sq, decrypted_result);
	vector<double> result;
	encoder.decode(decrypted_result, result);
	cout << "    + Computed result ...... Correct." << endl;
	print_vector(result, 4, 9);

}