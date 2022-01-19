package com.provider.messagedigest.digest;


import org.bouncycastle.util.Arrays;

public class KeccakDigest implements IExtendedDigest {
    private static long[] KeccakRoundConstants = keccakInitializeRoundConstants();
    private static int[] KeccakRhoOffsets = keccakInitializeRhoOffsets();
    protected byte[] state;
    protected byte[] dataQueue;
    protected int rate;
    protected int bitsInQueue;
    protected int fixedOutputLength;
    protected boolean squeezing;
    protected int bitsAvailableForSqueezing;
    protected byte[] chunk;
    protected byte[] oneByte;
    long[] C;
    long[] tempA;
    long[] chiC;

    private static long[] keccakInitializeRoundConstants() {
        long[] keccakRoundConstants = new long[24];
        byte[] LFSRstate = new byte[]{1};

        for (int i = 0; i < 24; ++i) {
            keccakRoundConstants[i] = 0L;

            for (int j = 0; j < 7; ++j) {
                int bitPosition = (1 << j) - 1;
                if (LFSR86540(LFSRstate)) {
                    keccakRoundConstants[i] ^= 1L << bitPosition;
                }
            }
        }

        return keccakRoundConstants;
    }

    private static boolean LFSR86540(byte[] LFSR) {
        boolean result = (LFSR[0] & 1) != 0;
        if ((LFSR[0] & 128) != 0) {
            LFSR[0] = (byte) (LFSR[0] << 1 ^ 113);
        } else {
            LFSR[0] = (byte) (LFSR[0] << 1);
        }

        return result;
    }

    private static int[] keccakInitializeRhoOffsets() {
        int[] keccakRhoOffsets = new int[25];
        keccakRhoOffsets[0] = 0;
        int x = 1;
        int y = 0;

        for (int t = 0; t < 24; ++t) {
            keccakRhoOffsets[x % 5 + 5 * (y % 5)] = (t + 1) * (t + 2) / 2 % 64;
            int newX = (0 * x + 1 * y) % 5;
            int newY = (2 * x + 3 * y) % 5;
            x = newX;
            y = newY;
        }

        return keccakRhoOffsets;
    }

    private void clearDataQueueSection(int off, int len) {
        for (int i = off; i != off + len; ++i) {
            this.dataQueue[i] = 0;
        }

    }

    public KeccakDigest() {
        this(288);
    }

    public KeccakDigest(int bitLength) {
        this.state = new byte[200];
        this.dataQueue = new byte[192];
        this.C = new long[5];
        this.tempA = new long[25];
        this.chiC = new long[5];
        this.init(bitLength);
    }

    public KeccakDigest(KeccakDigest source) {
        this.state = new byte[200];
        this.dataQueue = new byte[192];
        this.C = new long[5];
        this.tempA = new long[25];
        this.chiC = new long[5];
        System.arraycopy(source.state, 0, this.state, 0, source.state.length);
        System.arraycopy(source.dataQueue, 0, this.dataQueue, 0, source.dataQueue.length);
        this.rate = source.rate;
        this.bitsInQueue = source.bitsInQueue;
        this.fixedOutputLength = source.fixedOutputLength;
        this.squeezing = source.squeezing;
        this.bitsAvailableForSqueezing = source.bitsAvailableForSqueezing;
        this.chunk = Arrays.clone(source.chunk);
        this.oneByte = Arrays.clone(source.oneByte);
    }

    @Override
    public String getAlgorithmName() {
        return "Keccak-" + this.fixedOutputLength;
    }

    @Override
    public int getDigestSize() {
        return this.fixedOutputLength / 8;
    }

    @Override
    public void update(byte in) {
        this.oneByte[0] = in;
        this.absorb(this.oneByte, 0, 8L);
    }

    @Override
    public void update(byte[] in, int inOff, int len) {
        this.absorb(in, inOff, (long) len * 8L);
    }

    @Override
    public int doFinal(byte[] out, int outOff) {
        this.squeeze(out, outOff, (long) this.fixedOutputLength);
        this.reset();
        return this.getDigestSize();
    }

    protected int doFinal(byte[] out, int outOff, byte partialByte, int partialBits) {
        if (partialBits > 0) {
            this.oneByte[0] = partialByte;
            this.absorb(this.oneByte, 0, (long) partialBits);
        }

        this.squeeze(out, outOff, (long) this.fixedOutputLength);
        this.reset();
        return this.getDigestSize();
    }

    @Override
    public void reset() {
        this.init(this.fixedOutputLength);
    }

    @Override
    public int getByteLength() {
        return this.rate / 8;
    }

    private void init(int bitLength) {
        switch (bitLength) {
            case 128:
                this.initSponge(1344, 256);
                break;
            case 224:
                this.initSponge(1152, 448);
                break;
            case 256:
                this.initSponge(1088, 512);
                break;
            case 288:
                this.initSponge(1024, 576);
                break;
            case 384:
                this.initSponge(832, 768);
                break;
            case 512:
                this.initSponge(576, 1024);
                break;
            default:
                throw new IllegalArgumentException("bitLength must be one of 128, 224, 256, 288, 384, or 512.");
        }

    }

    private void initSponge(int rate, int capacity) {
        if (rate + capacity != 1600) {
            throw new IllegalStateException("rate + capacity != 1600");
        } else if (rate > 0 && rate < 1600 && rate % 64 == 0) {
            this.rate = rate;
            Arrays.fill((byte[]) this.state, (byte) 0);
            Arrays.fill((byte[]) this.dataQueue, (byte) 0);
            this.bitsInQueue = 0;
            this.squeezing = false;
            this.bitsAvailableForSqueezing = 0;
            this.fixedOutputLength = capacity / 2;
            this.chunk = new byte[rate / 8];
            this.oneByte = new byte[1];
        } else {
            throw new IllegalStateException("invalid rate value");
        }
    }

    private void absorbQueue() {
        this.KeccakAbsorb(this.state, this.dataQueue, this.rate / 8);
        this.bitsInQueue = 0;
    }

    protected void absorb(byte[] data, int off, long databitlen) {
        if (this.bitsInQueue % 8 != 0) {
            throw new IllegalStateException("attempt to absorb with odd length queue");
        } else if (this.squeezing) {
            throw new IllegalStateException("attempt to absorb while squeezing");
        } else {
            long i = 0L;

            while (true) {
                while (i < databitlen) {
                    if (this.bitsInQueue == 0 && databitlen >= (long) this.rate && i <= databitlen - (long) this.rate) {
                        long wholeBlocks = (databitlen - i) / (long) this.rate;

                        for (long j = 0L; j < wholeBlocks; ++j) {
                            System.arraycopy(data, (int) ((long) off + i / 8L + j * (long) this.chunk.length), this.chunk, 0, this.chunk.length);
                            this.KeccakAbsorb(this.state, this.chunk, this.chunk.length);
                        }

                        i += wholeBlocks * (long) this.rate;
                    } else {
                        int partialBlock = (int) (databitlen - i);
                        if (partialBlock + this.bitsInQueue > this.rate) {
                            partialBlock = this.rate - this.bitsInQueue;
                        }

                        int partialByte = partialBlock % 8;
                        partialBlock -= partialByte;
                        System.arraycopy(data, off + (int) (i / 8L), this.dataQueue, this.bitsInQueue / 8, partialBlock / 8);
                        this.bitsInQueue += partialBlock;
                        i += (long) partialBlock;
                        if (this.bitsInQueue == this.rate) {
                            this.absorbQueue();
                        }

                        if (partialByte > 0) {
                            int mask = (1 << partialByte) - 1;
                            this.dataQueue[this.bitsInQueue / 8] = (byte) (data[off + (int) (i / 8L)] & mask);
                            this.bitsInQueue += partialByte;
                            i += (long) partialByte;
                        }
                    }
                }

                return;
            }
        }
    }

    private void padAndSwitchToSqueezingPhase() {
        byte[] var10000;
        int var10001;
        if (this.bitsInQueue + 1 == this.rate) {
            var10000 = this.dataQueue;
            var10001 = this.bitsInQueue / 8;
            var10000[var10001] = (byte) (var10000[var10001] | 1 << this.bitsInQueue % 8);
            this.absorbQueue();
            this.clearDataQueueSection(0, this.rate / 8);
        } else {
            this.clearDataQueueSection((this.bitsInQueue + 7) / 8, this.rate / 8 - (this.bitsInQueue + 7) / 8);
            var10000 = this.dataQueue;
            var10001 = this.bitsInQueue / 8;
            var10000[var10001] = (byte) (var10000[var10001] | 1 << this.bitsInQueue % 8);
        }

        var10000 = this.dataQueue;
        var10001 = (this.rate - 1) / 8;
        var10000[var10001] = (byte) (var10000[var10001] | 1 << (this.rate - 1) % 8);
        this.absorbQueue();
        if (this.rate == 1024) {
            this.KeccakExtract1024bits(this.state, this.dataQueue);
            this.bitsAvailableForSqueezing = 1024;
        } else {
            this.KeccakExtract(this.state, this.dataQueue, this.rate / 64);
            this.bitsAvailableForSqueezing = this.rate;
        }

        this.squeezing = true;
    }

    protected void squeeze(byte[] output, int offset, long outputLength) {
        if (!this.squeezing) {
            this.padAndSwitchToSqueezingPhase();
        }

        if (outputLength % 8L != 0L) {
            throw new IllegalStateException("outputLength not a multiple of 8");
        } else {
            int partialBlock;
            for (long i = 0L; i < outputLength; i += (long) partialBlock) {
                if (this.bitsAvailableForSqueezing == 0) {
                    this.keccakPermutation(this.state);
                    if (this.rate == 1024) {
                        this.KeccakExtract1024bits(this.state, this.dataQueue);
                        this.bitsAvailableForSqueezing = 1024;
                    } else {
                        this.KeccakExtract(this.state, this.dataQueue, this.rate / 64);
                        this.bitsAvailableForSqueezing = this.rate;
                    }
                }

                partialBlock = this.bitsAvailableForSqueezing;
                if ((long) partialBlock > outputLength - i) {
                    partialBlock = (int) (outputLength - i);
                }

                System.arraycopy(this.dataQueue, (this.rate - this.bitsAvailableForSqueezing) / 8, output, offset + (int) (i / 8L), partialBlock / 8);
                this.bitsAvailableForSqueezing -= partialBlock;
            }

        }
    }

    private void fromBytesToWords(long[] stateAsWords, byte[] state) {
        for (int i = 0; i < 25; ++i) {
            stateAsWords[i] = 0L;
            int index = i * 8;

            for (int j = 0; j < 8; ++j) {
                stateAsWords[i] |= ((long) state[index + j] & 255L) << 8 * j;
            }
        }

    }

    private void fromWordsToBytes(byte[] state, long[] stateAsWords) {
        for (int i = 0; i < 25; ++i) {
            int index = i * 8;

            for (int j = 0; j < 8; ++j) {
                state[index + j] = (byte) ((int) (stateAsWords[i] >>> 8 * j & 255L));
            }
        }

    }

    private void keccakPermutation(byte[] state) {
        long[] longState = new long[state.length / 8];
        this.fromBytesToWords(longState, state);
        this.keccakPermutationOnWords(longState);
        this.fromWordsToBytes(state, longState);
    }

    private void keccakPermutationAfterXor(byte[] state, byte[] data, int dataLengthInBytes) {
        for (int i = 0; i < dataLengthInBytes; ++i) {
            state[i] ^= data[i];
        }

        this.keccakPermutation(state);
    }

    private void keccakPermutationOnWords(long[] state) {
        for (int i = 0; i < 24; ++i) {
            this.theta(state);
            this.rho(state);
            this.pi(state);
            this.chi(state);
            this.iota(state, i);
        }

    }

    private void theta(long[] A) {
        int x;
        for (x = 0; x < 5; ++x) {
            this.C[x] = 0L;

            for (int y = 0; y < 5; ++y) {
                long[] var10000 = this.C;
                var10000[x] ^= A[x + 5 * y];
            }
        }

        for (x = 0; x < 5; ++x) {
            long dX = this.C[(x + 1) % 5] << 1 ^ this.C[(x + 1) % 5] >>> 63 ^ this.C[(x + 4) % 5];

            for (int y = 0; y < 5; ++y) {
                A[x + 5 * y] ^= dX;
            }
        }

    }

    private void rho(long[] A) {
        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                int index = x + 5 * y;
                A[index] = KeccakRhoOffsets[index] != 0 ? A[index] << KeccakRhoOffsets[index] ^ A[index] >>> 64 - KeccakRhoOffsets[index] : A[index];
            }
        }

    }

    private void pi(long[] A) {
        System.arraycopy(A, 0, this.tempA, 0, this.tempA.length);

        for (int x = 0; x < 5; ++x) {
            for (int y = 0; y < 5; ++y) {
                A[y + 5 * ((2 * x + 3 * y) % 5)] = this.tempA[x + 5 * y];
            }
        }

    }

    private void chi(long[] A) {
        for (int y = 0; y < 5; ++y) {
            int x;
            for (x = 0; x < 5; ++x) {
                this.chiC[x] = A[x + 5 * y] ^ ~A[(x + 1) % 5 + 5 * y] & A[(x + 2) % 5 + 5 * y];
            }

            for (x = 0; x < 5; ++x) {
                A[x + 5 * y] = this.chiC[x];
            }
        }

    }

    private void iota(long[] A, int indexRound) {
        A[0] ^= KeccakRoundConstants[indexRound];
    }

    private void KeccakAbsorb(byte[] byteState, byte[] data, int dataInBytes) {
        this.keccakPermutationAfterXor(byteState, data, dataInBytes);
    }

    private void KeccakExtract1024bits(byte[] byteState, byte[] data) {
        System.arraycopy(byteState, 0, data, 0, 128);
    }

    private void KeccakExtract(byte[] byteState, byte[] data, int laneCount) {
        System.arraycopy(byteState, 0, data, 0, laneCount * 8);
    }
}
