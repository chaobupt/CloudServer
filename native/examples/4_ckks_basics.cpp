// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "examples.h"

using namespace std;
using namespace seal;

void example_ckks_basics()
{
    print_example_banner("Example: CKKS Basics");

    /*
    In this example we demonstrate evaluating a polynomial function 多项式函数的求值

        PI*x^3 + 0.4*x + 1

    on encrypted floating-point input data x for a set of 4096 equidistant points	加密的浮点数输入数据x是区间[0,1]上的4096个等间距点的集合
    in the interval [0, 1]. This example demonstrates many of the main features
    of the CKKS scheme, but also the challenges in using it.

    We start by setting up the CKKS scheme.
    */
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
    size_t poly_modulus_degree = 8192;
    parms.set_poly_modulus_degree(poly_modulus_degree);
    parms.set_coeff_modulus(CoeffModulus::Create(poly_modulus_degree, { 60, 40, 40, 60 }));

    /*
    We choose the initial scale to be 2^40. At the last level, this leaves us		我们选择初始scale 为2^40。最后一层，剩下60-40=小数点前20位的精度，足够了10-20位)小数点后的精度。
    60-40=20 bits of precision before the decimal point, and enough (roughly		因为我们中间素数是40bits(事实上，它们非常接近2的40次方)，我们可以实现如上所述的规模稳定。
    10-20 bits) of precision after the decimal point. Since our intermediate
    primes are 40 bits (in fact, they are very close to 2^40), we can achieve
    scale stabilization as described above.
    */
    double scale = pow(2.0, 40);			//定义编码精度的scale参数

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
        input.push_back(curr_point);			//输入为等间距的4096个double数值
    }
    cout << "Input vector: " << endl;    
    print_vector(input, 3, 7); //精度为小数点后7位

    cout << "Evaluating polynomial PI*x^3 + 0.4x + 1 ..." << endl;

    /*
    We create plaintexts for PI, 0.4, and 1 using an overload of CKKSEncoder::encode	我们使用一个重载的CKKSEncoder::encode为PI、0.4和1创建明文，它将给定的浮点值编码到向量的每个slot中。
    that encodes the given floating-point value to every slot in the vector.
    */
    Plaintext plain_coeff3, plain_coeff1, plain_coeff0;
    encoder.encode(3.14159265, scale, plain_coeff3);// Encodes a double-precision floating-point real number into a plaintext polynomial.
    encoder.encode(0.4, scale, plain_coeff1);
    encoder.encode(1.0, scale, plain_coeff0);

    Plaintext x_plain;
    print_line(__LINE__);
    cout << "Encode input vectors." << endl;
    encoder.encode(input, scale, x_plain);		//将向量input编码到明文x_plain  Encodes a vector of double-precision floating-point real or complex numbers into a plaintext polynomial.
    Ciphertext x1_encrypted;
    encryptor.encrypt(x_plain, x1_encrypted);	//x_plain---加密--->x1_encrypted

    /*
    To compute x^3 we first compute x^2 and relinearize. However, the scale has       
    now grown to 2^80.
    */
    Ciphertext x3_encrypted;
    print_line(__LINE__);
    cout << "Compute x^2 and relinearize:" << endl;
    evaluator.square(x1_encrypted, x3_encrypted);			 //先计算x^2再线性化  scale=2^80
    evaluator.relinearize_inplace(x3_encrypted, relin_keys);
    cout << "    + Scale of x^2 before rescale: " << log2(x3_encrypted.scale())
        << " bits" << endl;

    /*
    Now rescale; in addition to a modulus switch, the scale is reduced down by			rescale
    a factor equal to the prime that was switched away (40-bit prime). Hence, the		除了模数转换之外，scale还会受一个因子影响而减少，这个因子等于被切换掉的素数(40位素数)。
    new scale should be close to 2^40. Note, however, that the scale is not equal		新的scale应该接近2的40次方。但是注意，scale不等于2的40次方:这是因为40位素数只接近2的40次方。
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
    Next we compute the degree one term. All this requires is one multiply_plain   计算一次项0.4*x
    with plain_coeff1. We overwrite x1_encrypted with the result.					将结果重写进x1_encrypted
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
    Now we would hope to compute the sum of all three terms. However, there is	这三个项所使用的加密参数都是不同的，这是由于从rescaling进行modulus switching的结果。
    a serious problem: the encryption parameters used by all three terms are
    different due to modulus switching from rescaling.
    Encrypted addition and subtraction require that the scales of the inputs are	加密的加法和减法要求输入的scale相同，并且加密参数(parms_id)匹配。如果不匹配，求值程序将抛出异常。
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
    primes in coeff_modulus as P_0, P_1, P_2, P_3, in this order. P_3 is used as        P_3用作special modulus 并且不参与rescaling
    the special modulus and is not involved in rescalings. After the computations
    above the scales in ciphertexts are:经过以上的计算密文中的scale:

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
    There are many ways to fix this problem. Since P_2 and P_1 are really close			问题一：三个项的scale不完全一样
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
    We still have a problem with mismatching encryption parameters. This is easy		问题二：三个项的encryption parameters不匹配
    to fix by using traditional modulus switching (no rescaling). CKKS supports			这很容易修复 使用传统的模量开关(没有rescaling)。
    modulus switching just like the BFV scheme, allowing us to switch away parts		CKKS支持模量转换就像BFV方案一样，允许我们在根本不需要的时候转换系数模量coefficent modulus的一部分。
    of the coefficient modulus when it is simply not needed.
    */
    print_line(__LINE__);
    cout << "Normalize encryption parameters to the lowest level." << endl;		//将加密参数规格化为最低level
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