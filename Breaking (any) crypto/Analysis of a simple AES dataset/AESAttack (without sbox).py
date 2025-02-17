import TRS_Reader
import numpy as np
from scipy.stats import pearsonr
import matplotlib.pyplot as plt

class AESAttack(object):
    global key
    key = [0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c]

    def ADK(self, X, k):
        y = np.zeros(len(X)).astype(int)
        for i in range(len(X)):
            y[i]=X[i]^k
        return y

    def HW(self, X):
        y=np.zeros(len(X)).astype(int)
        for i in range(len(X)):
            y[i]=bin(X[i]).count("1")
        return y

    def maxCorr(self, hw, traces):
        maxcorr = 0
        corr = np.zeros(trs.number_of_samples)
        for i in range(trs.number_of_samples):
            [corr[i], pv ]= pearsonr(hw, traces[:, i])
            if abs(corr[i]) > maxcorr:
                maxcorr = abs(corr[i])
        return [maxcorr, corr]

    def Initialise(self, N):
        trs = TRS_Reader.TRS_Reader("TinyAES_625Samples_FirstRoundSbox.trs")
        trs.read_header()
        trs.read_traces(N, 0, trs.number_of_samples)
        HWguess = np.zeros((16, 256, N)).astype(int)
        for byteno in range(16):
            X = trs.plaintext[:,byteno]
            print("byteno={0}\n".format(byteno))
            for kg in range(256):
                Y=AESAttack().ADK(X, kg)
                HWguess[byteno,kg]=AESAttack().HW(Y)
        return [trs, HWguess]

    def corrAttack(self, trs, ax, byteno, Nm):
        ax.clear()
        maxkg = 0
        maxcorr_k = 0
        for kg in range(256):
            hw = HWguess[byteno, kg]
            [maxcorr, corr] = AESAttack().maxCorr(hw[0:Nm], trs.traces[0:Nm,:])
            if maxcorr > maxcorr_k:
                maxkg = kg
                maxcorr_k = maxcorr
            if kg == key[byteno]:
                ax.plot(corr, 'r-', alpha=1, label="True Key")
            else:
                ax.plot(corr, color=(0.8, 0.8, 0.8), alpha=0.8)
        ax.set_xlim([1, trs.number_of_samples])
        ax.set_ylim([-1, 1])
        ax.set_title(f'Byte {byteno}=0x{maxkg:02x}')
        ax.set_xlabel('Samples')
        ax.set_ylabel(r'$\rho$')
        return maxkg

if __name__ == '__main__':
    [trs,HWguess]=AESAttack().Initialise(1000)
    plt.ion()
    fig = plt.figure()
    ax = []
    for byteno in range(16):
        ax.append(fig.add_subplot(4, 4, byteno+1))
    for Nm in range(20,21) :
        fig.suptitle('N={0}'.format(Nm * 50))
        print("N={0}\n".format(Nm*50))
        for byteno in range(16):
            print("byte={0}\n".format(byteno))
            AESAttack().corrAttack(trs, ax[byteno], byteno, Nm*50)
            fig.canvas.draw()
            fig.canvas.flush_events()
            plt.show()
            plt.tight_layout()
            plt.pause(.001)
    plt.ioff()
    plt.show()
