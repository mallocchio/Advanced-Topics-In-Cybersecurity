import random
import toy_ciphers
from pprint import pprint

def difference_distribution_table(sbox):

    d_dist_table= [[0 for row in range(len(sbox))] for col in range(len(sbox))]

    for x in range(len(sbox)):
        for x_d in range(len(sbox)):
            d_in = x ^ x_d

            y = sbox[x]
            y_d = sbox[x_d]
            d_out = y ^ y_d

            d_dist_table[d_in][d_out] = d_dist_table[d_in][d_out] +1

    return d_dist_table

def get_good_pairs(d_in, d_out, sbox):

    pairs= []

    for x in range(len(sbox)):
        x_d = x ^ d_in
        y = sbox[x]
        y_d = sbox[x_d]
        d_out_test = y ^ y_d
        if d_out_test == d_out:
            pairs.append((x,y))

    return pairs

if __name__=="__main__":

    # demo for the principle of differential cryptanalysis
    # the demo is for the 3 bit, single round cipher, features two independent subkeys
    # grab the corresponding sbox from the toy_ciphers
    s_box = toy_ciphers.s_3b
    inv_s_box = [s_box.index(i) for i in range(len(s_box))]

    diff_dist_table = difference_distribution_table(s_box)
    print('Difference table:\n')
    pprint(diff_dist_table)
    print('')
    # find a good difference pair via a visual inspection of the table,
    # one such choice is used in the next line
    good_difference = (2,4)
    good_pairs = get_good_pairs(good_difference[0],good_difference[1], s_box)
    print('For the input-output difference',good_difference,'the good (u,v) pairs are:')
    pprint(good_pairs)
    print('')
    # pick a message (at random) and then find the corresponding
    # second message via a good differential, repeat until we find
    # a good output differential
    good_input=[]
    for m in range(8):
        m_d = m^good_difference[0]
        c =  toy_ciphers.encrypt_sub_1r(m)
        c_d= toy_ciphers.encrypt_sub_1r(m_d)
        if c^c_d == good_difference[1]:
            good_input.append(((m,m_d),(c,c_d)))
    print('For the above input-output difference, the good input-output pairs ((m, m+delta_m),(c, c+delta_c)) are:')
    pprint(good_input)
    print('')


    # pick a good pair (or try as many as there are according to the selected differential)
    # and work out the keys

    # we know that m + k0 must be one of the inputs to the sbox according to the differential
    # (and there are only a few according to our characteristic that are possible)
    # we also know that c+k1 must be one of the outputs of the sbox accord. to the differential
    k0_list: list[int] = [0]*len(good_pairs)
    k1_list: list[int] = [0]*len(good_pairs)

    for i in range(len(good_pairs)):
        k0_list[i]= good_pairs[i][0] ^ good_input[0][0][0]
        k1_list[i]= good_pairs[i][1] ^ good_input[0][1][0]


    print('Candidates for k0:', k0_list)
    print('Candidates for k1:', k1_list)
    message = random.randint(0, 7)
    for i in range(len(k0_list)):

        cipher = toy_ciphers.encrypt_sub_1r(message)
        challenge = s_box[message^k0_list[i]]^k1_list[i]

        if cipher==challenge:
            print('Message: ', message)
            print('Keys:',k0_list[i],k1_list[i])