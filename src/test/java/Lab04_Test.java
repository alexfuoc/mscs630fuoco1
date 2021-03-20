import org.junit.jupiter.api.Test;
import labs.AESCipher;

import static org.junit.jupiter.api.Assertions.assertEquals;

public class Lab04_Test {

    @Test
    void sample_test(){
        String key = "5468617473206D79204B756E67204675";
        String[] expandedKeys = {
                "5468617473206D79204B756E67204675",
                "E232FCF191129188B159E4E6D679A293",
                "56082007C71AB18F76435569A03AF7FA",
                "D2600DE7157ABC686339E901C3031EFB",
                "A11202C9B468BEA1D75157A01452495B",
                "B1293B3305418592D210D232C6429B69",
                "BD3DC287B87C47156A6C9527AC2E0E4E",
                "CC96ED1674EAAA031E863F24B2A8316A",
                "8E51EF21FABB4522E43D7A0656954B6C",
                "BFE2BF904559FAB2A16480B4F7F1CBD8",
                "28FDDEF86DA4244ACCC0A4FE3B316F26"};

        String[] outputKeys = AESCipher.aesRoundKeys(key);

        for(int i = 0; i < expandedKeys.length; i ++){
            System.out.print("Round: " + i + "\n");
            System.out.print("Expected: " + expandedKeys[i] + "\n");
            System.out.print("Got:      " + outputKeys[i] + "\n\n");

            assertEquals(expandedKeys[i], outputKeys[i]);
        }
    }
}