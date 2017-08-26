/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.generators;

import java.util.Arrays;
import java.math.BigInteger;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.Blake2b256Gadget;

public class Blake2b256CircuitGenerator extends CircuitGenerator {

    private Wire[] chunks;
	private int chunksLen;
	private Blake2b256Gadget Blake2b256Gadget;

	public Blake2b256CircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		int inputLen = 64 + 128;
		int padLen = (inputLen + 127) & (~127);
		chunksLen = padLen / 8; //chunk size is 64bit(8bytes)
		chunks = createInputWireArray(chunksLen);
		Wire[] digest = new Blake2b256Gadget(chunks, 64, 16, "").getOutputWires();
		makeOutputArray(digest);
	}

	@Override
	public void generateSampleInput(CircuitEvaluator e) {
		String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
        String keyStr = "ZcashComputehSig";
		byte[] chunksBuf = new byte[chunksLen*8];
		Arrays.fill(chunksBuf, (byte)0);
		System.arraycopy(keyStr.getBytes(), 0, chunksBuf, 0, keyStr.length());
		System.arraycopy(inputStr.getBytes(), 0, chunksBuf, 128, inputStr.length());
		BigInteger[] values = new BigInteger[chunksLen];
		for (int i = 0; i < chunksLen; i++) {
			byte[] tmp = new byte[8];
			for (int j = 0; j < 8; j++) {
				tmp[j] = chunksBuf[i * 8 + 8 - 1 - j];
			}
			values[i] = new BigInteger(tmp);
		}
		e.setWireValue(chunks, values);
	}

	public static void main(String[] args) throws Exception {
		Blake2b256CircuitGenerator generator = new Blake2b256CircuitGenerator("balke2b256");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}