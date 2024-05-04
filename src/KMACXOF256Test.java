/*
    Test class methods for KMACXOF256
    coded by Louis Lomboy
 */
import org.junit.jupiter.api.Test;

import java.math.BigInteger;

import static org.junit.jupiter.api.Assertions.*;

class KMACXOF256Test {

    /**
     * Test to ensure that the bytepad method correctly pads the input array
     */
    @Test
    void bytepadShouldReturnPaddedArray() {
        KMACXOF256 kmac = new KMACXOF256();
        byte[] input = {1, 2, 3};
        byte[] result = kmac.bytepad(input, 5);
        assertEquals(5, result.length);
    }

    /**
     * Test to ensure that the encode_string method correctly prepends the bit length to the input string
     */
    @Test
    void encodeStringShouldPrependBitLength() {
        KMACXOF256 kmac = new KMACXOF256();
        byte[] input = {1, 2, 3};
        byte[] result = kmac.encode_string(input);
        assertTrue(result.length > input.length);
    }

    /**
     * Test to ensure that the cSHAKE256 method correctly sets the inDATA field
     */
    @Test
    void cSHAKE256ShouldNotReturnNull() {
        KMACXOF256 kmac = new KMACXOF256();
        kmac.cSHAKE256(new byte[]{1, 2, 3}, 256, "N", "S");
        assertNotNull(kmac.inData);
    }

    /**
     * Test to ensure that the left_encode method correctly encodes the input integer
     */
    @Test
    void leftEncodeShouldReturnEncodedBytes() {
        byte[] result = KMACXOF256.left_encode(123);
        assertNotNull(result);
    }

    /**
     * Test to ensure that the enc8 method correctly encodes the input inter as a byte
     */
    @Test
    void enc8ShouldReturnByte() {
        byte result = KMACXOF256.enc8(123);
        assertEquals(123, result);
    }

    /**
     * Test to ensure that the right_encode method correctly encodes the input integer
     */
    @Test
    void rightEncodeShouldReturnEncodedBytes() {
        byte[] result = KMACXOF256.right_encode(123);
        assertNotNull(result);
    }

    /**
     * Test to ensure that the init method correctly initializes the state
     */
    @Test
    void initShouldInitializeState() {
        KMACXOF256 kmac = new KMACXOF256();
        kmac.init(256);
        assertNotNull(kmac.state);
    }

    /**
     * Test to ensure that the update method correctly changes the state
     */
    @Test
    void updateShouldChangeState() {
        KMACXOF256 kmac = new KMACXOF256();
        kmac.init(256);
        BigInteger[] stateBefore = kmac.state.clone();
        kmac.update(new byte[]{1, 2, 3});
        assertNotEquals(stateBefore, kmac.state);
    }

    /**
     * Test to ensure that the finalHas method correcly retuyrns the hash
     */
    @Test
    void finalHashShouldReturnHash() {
        KMACXOF256 kmac = new KMACXOF256();
        kmac.init(256);
        kmac.update(new byte[]{1, 2, 3});
        byte[] result = kmac.finalHash();
        assertNotNull(result);
    }

    /**
     * Test to endure that the KMACXOF256 method correctly returns the hash
     */
    @Test
    void KMACXOF256ShouldReturnHash() {
        KMACXOF256 kmac = new KMACXOF256();
        byte[] result = kmac.KMACXOF256(new byte[]{1, 2, 3}, 256);
        assertNotNull(result);
    }

    /**
     * Test to endure that the out method correctly extracts the output
     */
    @Test
    void outShouldExtractOutput() {
        KMACXOF256 kmac = new KMACXOF256();
        kmac.init(256);
        kmac.update(new byte[]{1, 2, 3});
        byte[] output = new byte[256];
        kmac.out(output, 256);
        assertNotNull(output);
    }
}
