// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
    print_example_banner("Example: CKKS Basics");

    /*
    In this example we demonstrate evaluating a polynomial function ����ʽ��������ֵ

        PI*x^3 + 0.4*x + 1

    on encrypted floating-point input data x for a set of 4096 equidistant points	���ܵĸ�������������x������[0,1]�ϵ�4096���ȼ���ļ���
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
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
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    /*
    We choose the initial scale to be 2^40. At the last level, this leaves us		����ѡ���ʼscale Ϊ2^40�����һ�㣬ʣ��60-40=С����ǰ20λ�ľ��ȣ��㹻��10-20λ)С�����ľ��ȡ�
    60-40=20 bits of precision before the decimal point, and enough (roughly		��Ϊ�����м�������40bits(��ʵ�ϣ����Ƿǳ��ӽ�2��40�η�)�����ǿ���ʵ�����������Ĺ�ģ�ȶ���
    10-20 bits) of precision after the decimal point. Since our intermediate
    primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    scale stabilization as described above.
    */
    double scale = pow(2.0, 40);			//������뾫�ȵ�scale����

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

    vector<double> input;
    input.reserve(slot_count);
    double curr_point = 0;
    double step_size = 1.0 / (static_cast<double>(slot_count) - 1);
    for (size_t i = 0; i < slot_count; i++, curr_point += step_size)
    {
        input.push_back(curr_point);			//����Ϊ�ȼ���4096��double��ֵ
    }
    cout << "Input vector: " << endl;    
    print_vector(input, 3, 7); //����ΪС�����7λ

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode	����ʹ��һ�����ص�CKKSEncoder::encodeΪPI��0.4��1�������ģ����������ĸ���ֵ���뵽������ÿ��slot�С�
    that encodes the given floating-point value to every slot in the vector.
    */
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);// Encodes a double-precision floating-point real number into a plaintext polynomial.
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);		//������input���뵽����x_plain  Encodes a vector of double-precision floating-point real or complex numbers into a plaintext polynomial.
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);	//x_plain---����--->x1_encrypted

    /*
    To compute x^3 we first compute x^2 and relinearize. However, the scale has       
    now grown to 2^80.
    */
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);			 //�ȼ���x^2�����Ի�  scale=2^80
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale())
        << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by			rescale
    a factor equal to the prime that was switched away (40-bit prime). Hence, the		����ģ��ת��֮�⣬scale������һ������Ӱ������٣�������ӵ��ڱ��л���������(40λ����)��
    new scale should be close to 2^40. Note, however, that the scale is not equal		�µ�scaleӦ�ýӽ�2��40�η�������ע�⣬scale������2��40�η�:������Ϊ40λ����ֻ�ӽ�2��40�η���
    to 2^40: this is because the 40-bit prime is only close to 2^40.
    */
    print_line(__LINE__);
    cout << "Rescale x^2." << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of x^2 after rescale: " << log2(x3_encrypted.scale())
        << " bits" << endl;

    /*
    Now x3_encrypted is at a different level than x1_encrypted, which prevents us
    from multiplying them to compute x^3. We could simply switch x1_encrypted to
    the next parameters in the modulus switching chain. However, since we still
    need to multiply the x^3 term with PI (plain_coeff3), we instead compute PI*x
    first and multiply that with x^2 to obtain PI*x^3. To this end, we compute
    PI*x and rescale it back from scale 2^80 to something close to 2^40.
    */
    print_line(__LINE__);
    cout << "Compute and rescale PI*x." << endl;
    Ciphertext x1_encrypted_coeff3;
    evaluator.multiply_plain(x1_encrypted, plain_coeff3, x1_encrypted_coeff3);
    cout << "    + Scale of PI*x before rescale: " << log2(x1_encrypted_coeff3.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted_coeff3);
    cout << "    + Scale of PI*x after rescale: " << log2(x1_encrypted_coeff3.scale())
        << " bits" << endl;

    /*
    Since x3_encrypted and x1_encrypted_coeff3 have the same exact scale and use
    the same encryption parameters, we can multiply them together. We write the
    result to x3_encrypted, relinearize, and rescale. Note that again the scale
    is something close to 2^40, but not exactly 2^40 due to yet another scaling
    by a prime. We are down to the last level in the modulus switching chain.
    */
    print_line(__LINE__);
    cout << "Compute, relinearize, and rescale (PI*x)*x^2." << endl;
    evaluator.multiply_inplace(x3_encrypted, x1_encrypted_coeff3);
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of PI*x^3 before rescale: " << log2(x3_encrypted.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(x3_encrypted);
    cout << "    + Scale of PI*x^3 after rescale: " << log2(x3_encrypted.scale())
        << " bits" << endl;

    /*
    Next we compute the degree one term. All this requires is one multiply_plain   ����һ����0.4*x
    with plain_coeff1. We overwrite x1_encrypted with the result.					�������д��x1_encrypted
    */
    print_line(__LINE__);
    cout << "Compute and rescale 0.4*x." << endl;
    evaluator.multiply_plain_inplace(x1_encrypted, plain_coeff1);
    cout << "    + Scale of 0.4*x before rescale: " << log2(x1_encrypted.scale())
        << " bits" << endl;
    evaluator.rescale_to_next_inplace(x1_encrypted);
    cout << "    + Scale of 0.4*x after rescale: " << log2(x1_encrypted.scale())
        << " bits" << endl;

    /*
    Now we would hope to compute the sum of all three terms. However, there is	����������ʹ�õļ��ܲ������ǲ�ͬ�ģ��������ڴ�rescaling����modulus switching�Ľ����
    a serious problem: the encryption parameters used by all three terms are
    different due to modulus switching from rescaling.
    Encrypted addition and subtraction require that the scales of the inputs are	���ܵļӷ��ͼ���Ҫ�������scale��ͬ�����Ҽ��ܲ���(parms_id)ƥ�䡣�����ƥ�䣬��ֵ�����׳��쳣��
    the same, and also that the encryption parameters (parms_id) match. If there
    is a mismatch, Evaluator will throw an exception.
    */
    cout << endl;
    print_line(__LINE__);
    cout << "Parameters used by all three terms are different." << endl;
    cout << "    + Modulus chain index for x3_encrypted: "
        << context->get_context_data(x3_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for x1_encrypted: "
        << context->get_context_data(x1_encrypted.parms_id())->chain_index() << endl;
    cout << "    + Modulus chain index for plain_coeff0: "
        << context->get_context_data(plain_coeff0.parms_id())->chain_index() << endl;
    cout << endl;

    /*
    Let us carefully consider what the scales are at this point. We denote the
    primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as        P_3����special modulus ���Ҳ�����rescaling
    the special modulus and is not involved in rescalings. After the computations
    above the scales in ciphertexts are:�������ϵļ��������е�scale:

        - Product x^2 has scale 2^80 and is at level 2;                  
        - Product PI*x has scale 2^80 and is at level 2;
        - We rescaled both down to scale 2^80/P_2 and level 1;
        - Product PI*x^3 has scale (2^80/P_2)^2;
        - We rescaled it down to scale (2^80/P_2)^2/P_1 and level 0;		PI*x^3------level 0
        - Product 0.4*x has scale 2^80;
        - We rescaled it down to scale 2^80/P_2 and level 1;				0.4*x -------level 1
        - The contant term 1 has scale 2^40 and is at level 2.				1    --------level 2

    Although the scales of all three terms are approximately 2^40, their exact
    values are different, hence they cannot be added together.
    */
    print_line(__LINE__);
    cout << "The exact scales of all three terms are different:" << endl;
    ios old_fmt(nullptr);
    old_fmt.copyfmt(cout);
    cout << fixed << setprecision(10);
    cout << "    + Exact scale in PI*x^3: " << x3_encrypted.scale() << endl;
    cout << "    + Exact scale in  0.4*x: " << x1_encrypted.scale() << endl;
    cout << "    + Exact scale in      1: " << plain_coeff0.scale() << endl;
    cout << endl;
    cout.copyfmt(old_fmt);

    /*
    There are many ways to fix this problem. Since P_2 and P_1 are really close			����һ���������scale����ȫһ��
    to 2^40, we can simply "lie" to Microsoft SEAL and set the scales to be the
    same. For example, changing the scale of PI*x^3 to 2^40 simply means that we
    scale the value of PI*x^3 by 2^120/(P_2^2*P_1), which is very close to 1.
    This should not result in any noticeable error.

    Another option would be to encode 1 with scale 2^80/P_2, do a multiply_plain
    with 0.4*x, and finally rescale. In this case we would need to additionally
    make sure to encode 1 with appropriate encryption parameters (parms_id).

    In this example we will use the first (simplest) approach and simply change
    the scale of PI*x^3 and 0.4*x to 2^40.
    */
    print_line(__LINE__);
    cout << "Normalize scales to 2^40." << endl;
    x3_encrypted.scale() = pow(2.0, 40);
    x1_encrypted.scale() = pow(2.0, 40);

    /*
    We still have a problem with mismatching encryption parameters. This is easy		��������������encryption parameters��ƥ��
    to fix by using traditional modulus switching (no rescaling). CKKS supports			��������޸� ʹ�ô�ͳ��ģ������(û��rescaling)��
    modulus switching just like the BFV scheme, allowing us to switch away parts		CKKS֧��ģ��ת������BFV����һ�������������ڸ�������Ҫ��ʱ��ת��ϵ��ģ��coefficent modulus��һ���֡�
    of the coefficient modulus when it is simply not needed.
    */
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl;		//�����ܲ������Ϊ���level
    parms_id_type last_parms_id = x3_encrypted.parms_id();
    evaluator.mod_switch_to_inplace(x1_encrypted, last_parms_id);
    evaluator.mod_switch_to_inplace(plain_coeff0, last_parms_id);

    /*
    All three ciphertexts are now compatible and can be added.
    */
    print_line(__LINE__);
    cout << "Compute PI*x^3 + 0.4*x + 1." << endl;
    Ciphertext encrypted_result;
    evaluator.add(x3_encrypted, x1_encrypted, encrypted_result);
    evaluator.add_plain_inplace(encrypted_result, plain_coeff0);

    /*
    First print the true result.
    */
    Plaintext plain_result;
    print_line(__LINE__);
    cout << "Decrypt and decode PI*x^3 + 0.4x + 1." << endl;
    cout << "    + Expected result:" << endl;
    vector<double> true_result;
	cout << input.size() << endl;
    for (size_t i = 0; i < input.size(); i++)
    {
        double x = input[i];
        true_result.push_back((3.14159265 * x * x + 0.4)* x + 1);
    }
    print_vector(true_result, 3, 7);

    /*
    Decrypt, decode, and print the result.
    */
    decryptor.decrypt(encrypted_result, plain_result);
    vector<double> result;
    encoder.decode(plain_result, result);          //Decodes a plaintext polynomial into double-precision floating-point real or complex numbers.
    cout << "    + Computed result ...... Correct." << endl;
    print_vector(result, 3, 7);

    /*
    While we did not show any computations on complex numbers in these examples,
    the CKKSEncoder would allow us to have done that just as easily. Additions
    and multiplications of complex numbers behave just as one would expect.
    */
}