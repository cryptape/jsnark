/*******************************************************************************
 * Author: zhiwei ning <rink1969@cryptape.com>
 *******************************************************************************/
package examples.generators;

import circuit.eval.CircuitEvaluator;
import circuit.structure.CircuitGenerator;
import circuit.structure.Wire;
import examples.gadgets.Blake2b256Gadget;

public class Blake2b256CircuitGenerator extends CircuitGenerator {

	private Wire[] inputWires;
	private Blake2b256Gadget Blake2b256Gadget;

	public Blake2b256CircuitGenerator(String circuitName) {
		super(circuitName);
	}

	@Override
	protected void buildCircuit() {
		
		// assuming the circuit input will be 64 bytes
		inputWires = createInputWireArray(64);
		// this gadget is not applying any padding.
		Blake2b256Gadget = new Blake2b256Gadget(inputWires, 8, 64, false, false);
		Wire[] digest = Blake2b256Gadget.getOutputWires();
		makeOutputArray(digest, "digest");		
	}

	@Override
	public void generateSampleInput(CircuitEvaluator evaluator) {
		String inputStr = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijkl";
		for (int i = 0; i < inputWires.length; i++) {
			evaluator.setWireValue(inputWires[i], inputStr.charAt(i));
		}
	}

	public static void main(String[] args) throws Exception {
		Blake2b256CircuitGenerator generator = new Blake2b256CircuitGenerator("balke2b256");
		generator.generateCircuit();
		generator.evalCircuit();
		generator.prepFiles();
		generator.runLibsnark();
	}
}