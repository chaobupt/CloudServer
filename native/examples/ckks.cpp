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
	We saw in `2_encoders.cpp' that multiplication in CKKS causes scales           CKKS中的乘法会造成密文中的scales增长， 任何密文的scale一定不能接近coeff_modulus 的总体size,
	in ciphertexts to grow. The scale of any ciphertext must not get too close		否则，密文就会耗尽空间来存储放大的明文。
	to the total size of coeff_modulus, or else the ciphertext simply runs out of
	room to store the scaled-up plaintext. The CKKS scheme provides a `rescale'
	functionality that can reduce the scale, and stabilize the scale expansion.		CKKS方案提供了一个“rescale”功能，可以减少scale，并稳定scale扩展。

	Rescaling is a kind of modulus switch operation (recall `3_levels.cpp').		rescale是一种模数转换操作(回忆一下' 3_levels.cpp')。在转换模量时，它会从coeff_modulo中移除最
	As modulus switching, it removes the last of the primes from coeff_modulus,		后一个素数，但作为副作用，它会通过移除的素数缩小密文的范围。通常，我们想要对scale如何变化有完美的控制，
	but as a side-effect it scales down the ciphertext by the removed prime.		这就是为什么在CKKS方案中，为coeff_moduls使用精心挑选的素数更为常见
	Usually we want to have perfect control over how the scales are changed,
	which is why for the CKKS scheme it is more common to use carefully selected
	primes for the coeff_modulus.

	More precisely, suppose that the scale in a CKKS ciphertext is S, and the		更精确地说，假设CKKS密文中的scale是S，并且当前的coeff_modulus(对于密文)中的最后一个素数是P。
	last prime in the current coeff_modulus (for the ciphertext) is P. Rescaling	rescaling调整到下一层将scale更改为S/P，并将素数P从coeff_modulus中移除，与模量切换中的通常做法一样。
	to the next level changes the scale to S/P, and removes the prime P from the	素数的数量限制了rescaling的次数，从而限制了计算的乘法深度。
	coeff_modulus, as usual in modulus switching. The number of primes limits
	how many rescalings can be done, and thus limits the multiplicative depth of
	the computation.

	It is possible to choose the initial scale freely. One good strategy can be		在coeff_modul_be中设置初始scale S和素数P_i为彼此非常接近
	to is to set the initial scale S and primes P_i in the coeff_modulus to be		如果密文在乘法之前有S scale，乘法之后是S^2，Rescaling 之后是S^2/P_i。
	very close to each other. If ciphertexts have scale S before multiplication,
	they have scale S^2 after multiplication, and S^2/P_i after rescaling. If all
	P_i are close to S, then S^2/P_i is close to S again. This way we stabilize the 这样我们就稳定了在整个计算过程中使得scale接近S
	scales to be close to S throughout the computation. Generally, for a circuit		一般来说，对于深度D的电路，我们需要Rescale D倍，即我们需要把素数D从系数模数中去掉。
	of depth D, we need to rescale D times, i.e., we need to be able to remove D
	primes from the coefficient modulus. Once we have only one prime left in the    一旦在coeff_modules中只剩下一个素数，剩下的素数必须比S大几个位，以保留明文的小数点前值。
	coeff_modulus, the remaining prime must be larger than S by a few bits to
	preserve the pre-decimal-point value of the plaintext.

	Therefore, a generally good strategy is to choose parameters for the CKKS
	scheme as follows:

		(1) Choose a 60-bit prime as the first prime in coeff_modulus. This will    选择一个60位素数作为coeff_modules中的第一个素数，这将解密时提供最高精度;
			give the highest precision when decrypting;
		(2) Choose another 60-bit prime as the last element of coeff_modulus, as    选择另一个60位素数作为coeff_modules的最后一个元素，这将被用作特殊的素数
			this will be used as the special prime and should be as large as the
			largest of the other primes;
		(3) Choose the intermediate primes to be close to each other.				选择的中间素数相近

	We use CoeffModulus::Create to generate primes of the appropriate size. Note    coeff_modulus 总共200bits, 这低于我们的poly_modulus_degree: coeff_modulus_degree::MaxBitCount(8192)返回218
	that our coeff_modulus is 200 bits total, which is below the bound for our
	poly_modulus_degree: CoeffModulus::MaxBitCount(8192) returns 218.
	*/

	size_t poly_modulus_degree = 8192; //degree of polynomial modulus 多项式模次数
	parms.set_poly_modulus_degree(poly_modulus_degree);
	parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 40, 40, 40, 40, 40})); //([ciphertext] coefficient modulus);(密文)模量系数

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
	print_vector(input1,4,9); //精度为小数点后9位

	vector<double> input2{0.020476542, -0.08371191, -0.038826868, 6.062781E-4 };
	cout << "Input vector2: " << endl;

	print_vector(input2,4,9); //精度为小数点后9位

	/*********************************************************计算（x1-x2）^2********************************************************************************************/
	cout << "Start Evaluating polynomial (x1-x2)^2 ..." << endl;

	Plaintext x1_plain, x2_plain;
	double scale = pow(2.0, 40);			//定义编码精度的scale参数
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
	encryptor.encrypt(x1_plain, x1_encrypted);	//x1_plain---加密--->x1_encrypted
	encryptor.encrypt(x2_plain, x2_encrypted);	//x2_plain---加密--->x2_encrypted

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