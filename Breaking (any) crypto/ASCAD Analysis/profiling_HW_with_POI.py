import h5py
import numpy as np
from scipy.stats import multivariate_normal

ASCAD_FILENAME = "ASCAD.h5"
SUBKEY_INDEX = 2       
NUM_KEY_VALUES = 256     
ALLOW_SINGULAR = True
POI_COUNT = 50

HW_table = np.array([bin(i).count("1") for i in range(256)], dtype=np.uint8)

SBOX = np.array([
    0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76,
    0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0,
    0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15,
    0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75,
    0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84,
    0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf,
    0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8,
    0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2,
    0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73,
    0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb,
    0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79,
    0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08,
    0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a,
    0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e,
    0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf,
    0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16
], dtype=np.uint8)

f = h5py.File(ASCAD_FILENAME, "r")

profiling_plain = np.array(f["Profiling_traces"]["metadata"]["plaintext"][:, SUBKEY_INDEX], dtype=np.uint8)
profiling_key = np.array(f["Profiling_traces"]["metadata"]["key"][:, SUBKEY_INDEX], dtype=np.uint8)
attack_plain = np.array(f["Attack_traces"]["metadata"]["plaintext"][:, SUBKEY_INDEX], dtype=np.uint8)
attack_key = np.array(f["Attack_traces"]["metadata"]["key"][:, SUBKEY_INDEX], dtype=np.uint8)

profiling_traces = np.array(f["Profiling_traces"]["traces"], dtype=np.float32)
profiling_labels = np.array(f["Profiling_traces"]["labels"], dtype=np.uint8)
attack_traces = np.array(f["Attack_traces"]["traces"], dtype=np.float32)
attack_labels = np.array(f["Attack_traces"]["labels"], dtype=np.uint8)

f.close()

real_subkey = profiling_key[0]
print(f"Real subkey byte = 0x{real_subkey:02X}")
print("Profiling set shape:", profiling_traces.shape)
print("Attack set shape:", attack_traces.shape)

HW_CLASSES = 9

profiling_hw = HW_table[profiling_labels]

num_points = profiling_traces.shape[1]

group_means      = np.zeros((HW_CLASSES, num_points), dtype=np.float32)
group_variances  = np.zeros((HW_CLASSES, num_points), dtype=np.float32)
group_counts     = np.zeros(HW_CLASSES, dtype=np.int32)

for hw in range(HW_CLASSES):
    idx = np.where(profiling_hw == hw)[0]
    if len(idx) > 0:
        group_traces = profiling_traces[idx, :]
        group_means[hw, :] = np.mean(group_traces, axis=0)
        group_variances[hw, :] = np.var(group_traces, axis=0)
        group_counts[hw] = len(idx)
    else:
        group_means[hw, :] = 0
        group_variances[hw, :] = 0

valid_groups = group_counts > 0
noise_var = np.mean(group_variances[valid_groups, :], axis=0)

signal_var = np.var(group_means[valid_groups, :], axis=0)

epsilon = 1e-12
SNR = signal_var / (noise_var + epsilon)

poi_indices = np.argsort(SNR)[-POI_COUNT:]
print(f"Selected {POI_COUNT} points of interest based on SNR.")

profiling_traces_poi = profiling_traces[:, poi_indices]
attack_traces_poi    = attack_traces[:, poi_indices]

mean_vectors = [None] * HW_CLASSES
covariance_matrices = [None] * HW_CLASSES
lambda_reg = 1e-6 

hw_groups = [[] for _ in range(HW_CLASSES)]
for i, label in enumerate(profiling_labels):
    hw_val = HW_table[label]
    hw_groups[hw_val].append(i)

for hw_val in range(HW_CLASSES):
    idx_list = hw_groups[hw_val]
    if len(idx_list) == 0:
        mean_vectors[hw_val] = np.zeros(POI_COUNT, dtype=np.float32)
        covariance_matrices[hw_val] = np.eye(POI_COUNT, dtype=np.float32)
    else:
        group_traces = profiling_traces_poi[idx_list, :]
        mean_vectors[hw_val] = np.mean(group_traces, axis=0)
        covariance_matrices[hw_val] = np.cov(group_traces, rowvar=False) + lambda_reg * np.eye(POI_COUNT)

print("Hamming Weight templates built using POI-selected traces.")

total_log_likelihoods = np.zeros(NUM_KEY_VALUES, dtype=np.float64)

for i, single_trace in enumerate(attack_traces_poi):
    for k_guess in range(NUM_KEY_VALUES):
        sbox_out = SBOX[attack_plain[i] ^ k_guess]
        hw_label = HW_table[sbox_out]
        
        mv = mean_vectors[hw_label]
        cv = covariance_matrices[hw_label]
        
        try:
            ll = multivariate_normal.logpdf(single_trace, mean=mv, cov=cv, allow_singular=ALLOW_SINGULAR)
        except np.linalg.LinAlgError:
            ll = -1e30 
        
        total_log_likelihoods[k_guess] += ll
        
predicted_key = np.argmax(total_log_likelihoods)
print(f"Predicted subkey = {predicted_key} (0x{predicted_key:02X})")
