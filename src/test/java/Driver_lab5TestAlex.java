import static org.junit.jupiter.api.Assertions.assertEquals;

import labs.AESCipher;
import org.junit.jupiter.api.Test;


public class Driver_lab5TestAlex {
    String error = "An error occurred.";

    @Test
    void test1() { //EXAMPLE
        String plainText = "54776F204F6E65204E696E652054776F";
        String keyHex = "5468617473206D79204B756E67204675";
        String cipherAnswer = "29C3505F571420F6402299B31A02D73A";

        assertEquals(cipherAnswer, AESCipher.AES(plainText, keyHex));
    }
    @Test
    void test2() { //MINE
        String plainText = "6D736373363330206165732074657374"; //mscs630 aes test
        String keyHex = "7468697320697320746865206B657921"; //this is the key!
        String cipherAnswer = "B639E8A9B9FC3BB7BAFAA92593CB75D6";

        assertEquals(cipherAnswer, AESCipher.AES(plainText, keyHex));
    }
    @Test
    void test3() { //MINE
        String plainText = "696E6565643136636861727368616861"; //ineed16charshaha
        String keyHex = "2179656B206568742073692073696874"; //!yek eht si siht
        String cipherAnswer = "CAF02C368D5B5C69B91DF799272DE82A";

        assertEquals(cipherAnswer, AESCipher.AES(plainText, keyHex));
    }

    @Test
    void test4() { //MINE
        String plainText = "48424B5349544557425150504F4B494E"; //HBKSITEWBQPPOKIN
        String keyHex = "696D696E353432333862786373776139"; //imin54238bxcswa9
        String cipherAnswer = "7752C847454B7203CE5B28BB5D33E46B";

        assertEquals(cipherAnswer, AESCipher.AES(plainText, keyHex));
    }

    @Test
    void test5() {
        String plainText = "73736F72732C204C697A6172642C2053";
        String keyHex = "526F636B2C2050617065722C20536369";
        String cipherAnswer = "57D43EBAEE7EEDCD443A10FF6FE0E325";

        assertEquals(cipherAnswer, AESCipher.AES(plainText, keyHex));
    }

    @Test
    void test6() {
        String plainText = "6E6720636F636F6E757473206D696772";
        String keyHex = "41726520796F75207375676765737469";
        String cipherAnswer = "036F1E119CFD4FEC53A4788C43060676";

        assertEquals(cipherAnswer, AESCipher.AES(plainText, keyHex));
    }

    @Test
    void test7() {
        String plainText = "61746E65737320697320726573706F6E";
        String keyHex = "546865207072696365206F6620677265";
        String cipherAnswer = "4E8F2B5B03E235D65372BC564F734CAA";

        assertEquals(cipherAnswer, AESCipher.AES(plainText, keyHex));
    }
}
