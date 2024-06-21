package keys

import "github.com/toxyl/errors"

// WeakKeyScrambler transforms a weak password into a more secure 32-byte password.
// The function uses a scrambling algorithm that ensures the resulting password
// contains only printable ASCII characters.
//
// Parameters:
//
//	key (string): The input key to be scrambled. It must not be empty.
//
// Returns:
//
//	string: A 32-byte scrambled key.
//	error: An error if the input key is empty.
//
// Example:
//
//	secureKey, err := keys.WeakKeyScrambler("weakpassword")
//	if err != nil {
//	    fmt.Println("Error:", err)
//	} else {
//	    fmt.Println("Scrambled Key:", secureKey)
//	}
func WeakKeyScrambler(key string) (string, error) {
	if len(key) == 0 {
		return "", errors.Newf("can't scramble, key cannot be empty")
	}

	// Helper function to constrain values to printable ASCII range
	wrapToPrintableASCII := func(i int) int { return (i % 0x5D) + 0x21 }

	scrambledKey := []byte{}
	currentShift := int(key[0]) - 0x21 // Calculate the initial shift value based on the ASCII value of the first character of the key

	for len(scrambledKey) < 32 {
		for i, b := range key {
			if len(scrambledKey) > 0 {
				currentShift = int(scrambledKey[len(scrambledKey)-1]) - 0x21 // Update the shift based on the last byte in scrambledKey
			}
			shiftedFirstByte := wrapToPrintableASCII(int(b) + currentShift + i)                                   // Shift the first byte
			shiftedLastByte := wrapToPrintableASCII(int(key[len(key)-i-1]) + currentShift + i)                    // Shift the last byte
			scrambledKey = append(scrambledKey, byte(wrapToPrintableASCII(shiftedFirstByte/2+shiftedLastByte/2))) // Append the average of both bytes

			if len(scrambledKey) >= 32 {
				break
			}
		}
	}

	return string(scrambledKey[:32]), nil
}
