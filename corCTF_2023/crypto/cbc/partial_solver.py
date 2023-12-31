# constants:
alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
bs = 16
iv = 'RLNZXWHLULXRLTNP'
ciphertext = 'ZQTJIHLVWMPBYIFRQBUBUESOOVCJHXXLXDKPBQCUXWGJDHJPQTHXFQIQMBXNVOIPJBRHJQOMBMNJSYCRAHQBPBSMMJWJKTPRAUYZVZTHKTPUAPGAIJPMZZZDZYGDTKFLWAQTSKASXNDRRQQDJVBREUXFULWGNSIINOYULFXLDNMGWWVSCEIORQESVPFNMWZKPIYMYVFHTSRDJWQBTWHCURSBPUKKPWIGXERMPXCHSZKYMFLPIAHKTXOROOJHUCSGINWYEILFIZUSNRVRBHVCJPVPSEGUSYOAMXKSUKSWSOJTYYCMEHEUNPJAYXXJWESEWNSCXBPCCIZNGOVFRTGKYHVSZYFNRDOVPNWEDDJYITHJUBVMWDNNNZCLIPOSFLNDDWYXMYVCEOHZSNDUXPIBKUJIJEYOETXWOJNFQAHQOVTRRXDCGHSYNDYMYWVGKCCYOBDTZZEQQEFGSPJJIAAWVDXFGPJKQJCZMTPMFZDVRMEGMPUEMOUVGJXXBRFCCCRVTUXYTTORMSQBLZUEHLYRNJAAIVCRFSHLLPOANFKGRWBYVSOBLCTDAUDVMMHYSYCDZTBXTDARWRTAFTCVSDRVEENLHOHWBOPYLMSDVOZRLENWEKGAWWCNLOKMKFWWAZJJPFDSVUJFCODFYIMZNZTMAFJHNLNMRMLQRTJJXJCLMQZMOFOGFPXBUTOBXUCWMORVUIIXELTVIYBLPEKKOXYUBNQONZLPMGWMGRZXNNJBUWBEFNVXUIAEGYKQSLYSDTGWODRMDBHKCJVWBNJFTNHEWGOZFEZMTRBLHCMHIFLDLORMVMOOHGXJQIIYHZFMROGUUOMXBTFMKERCTYXFIHVNFWWIUFTGLCKPJRFDRWDXIKLJJLNTWNQIOFWSIUQXMFFVIIUCDEDFEJNLKLQBALRKEYWSHESUJJXSHYWNRNPXCFUEFRJKSIGXHFTKNJXSYVITDOGYIKGJIOOHUFILWYRBTCQPRPNOKFKROTFZNOCZXZEYUNWJZDPJDGIZLWBBDGZJNRQRPFFGOTGFBACCRKLAPFLOGVYFXVIIJMBBMXWJGLPOQQHMNBCINRGZRBVSMLKOAFGYRUDOPCCULRBE'
blocks = [ciphertext[i:i+bs] for i in range(0, len(ciphertext), bs)]

###########################################
# decode logic:
def subtract_key(key, block):
	ct_idxs = [(pt_a - k_a) % len(alphabet) for k_a, pt_a in zip([alphabet.index(k) for k in key], [alphabet.index(pt) for pt in block])]
	return "".join([alphabet[idx] for idx in ct_idxs])
###########################################
# solution:

# Compute the differences (using subtract_key) between adjacent blocks to subtract the IV for each block
# thus only having to deal with the key - without the CBC effect.
def differences(iv, blocks):
	ds = []
	prev_block = iv
	for block in blocks:
		d = subtract_key(prev_block, block)
		ds += [d]
		prev_block = block
	return ds

block_differences = differences(iv, blocks)
print(''.join(block_differences))
# IFGKLLEKCBSKNPSCRLBSMXHTSJNIJPSUHCQOHMKGJBEAWKMETQXIEAGWPFRESHZATIKKEAGWPLQWXKUCRGZUGLEALXJASVNAANIYGYBVYKTLQWRJIPRNEAGWPFRJTVZLORBHTLBPYPXOYGLSNVLYMKXNXYTPWCSFETXDHLAGJCQAJENKPQKUGLHHSCTHQAESNEQYHFBPYDMQXARREOJQWWNUWCTHGASFEIKKVGKGDFAOXJDJLWQYEAMKWPZJIXHRANPOLLXOULLLTPDLTUZEFHKKKFMCFHTJLQPQLVXHAKDZGAOMSKUCTFREGJOQYGQSSGOIKMGCELCEKKDBVGOIBGGQXQGALPTQYUQUFWOGJVCWDYHRHQRJKWTNAWHJLKSRHTLKZZTRWZTHNCQRUTKEYWOGFQRPMGUCRUFEGGYIFRVDNEGGSYFTXDRWKBCPTFZWIULVMWGESIKAINHLUZXDWETPQLEEYUTQETPQKWGQLXVWWGSFAVFJBKUCKFBWQNXRHGDDNKRULBLZJXDJORBTUQMJWDMQUTNHEEQJAWKGJBZHQAHQANFDNPTPVQGAXGOCORIUTJXWKFMCNVASTKQYLBNULXOWWVNDTJBIRKMGEQGADWRCLKKKQALVZBJAWPDJTJBFKGZTSJHJYJDQYUQUFLACLXKHTEZREUQXXETEZFMAXTDQOWOSXKMQLEDKYJDPPTLWKSFULEZPDQTPUPQXXCXTFBKEXCMCSUBDMATNHXQPTHZLORBHTLBPYPXOYGLZUVRIXDXUKYXEYUDJFKQSTFHPDVEQSESGOPFDMZXEGKSACVNDAELCIDXVWLOAWCSGNIPOLLXODFMQCKRLOTJQEDRWKBCESENKBKKQMAHPOFSDYJDENWLFXJTVAKFODUSCMVEUPZHNWPXOYGLGSDXIBUTNDVFJZYHRHNFDNPTFVBCKWIMSLKKKQSENLEDOTEZJLGABBFNZVFRPWKASTKLDLSKGJBZHQACGSVOYUMMKGKRKKIMSLKKKQSGAOXXDJTDAOOBIMZXHDXFEYUDTETVJAAGISCSAWVGGSCQBXSLVAQRJTVZEEPBHBUKQLQGEWVDCNEEQEDXPYBHCZGRQ

# Based on the algorith used in 'add_key', this is just a rotational chiffre, thus we can treat this now as 
# a Vigenere cipher with key length 16:

# Using CrypTool to crack the remaining Vigenere-Cipher:
# Key: ACXQTSTCSXZWFCZY
# Solution: IDJUSTLIKETOINTERJECTFORAMOMENTWHATYOUREREFERINGTOASLINUXISINFACTGNULINUXORASIVERECENTLYTAKENTOCALLINGITGNUPLUSLINUXLINUXISNOTANOPERATINGSYSTEMUNTOITSELFBUTRATHERANOTHERFREECOMPONENTOFAFULLYFUNCTIONINGGNUSYSTEMMADEUSEFULBYTHEGNUCORELIBSSHELLUTILITIESANDVITALSYSTEMCOMPONENTSCOMPRISINGAFULLOSASDEFINEDBYPOSIXMANYCOMPUTERUSERSRUNAMODIFIEDVERSIONOFTHEGNUSYSTEMEVERYDAYWITHOUTREALIZINGITTHROUGHAPECULIARTURNOFEVENTSTHEVERSIONOFGNUWHICHISWIDELYUSEDTODAYISOFTENCALLEDLINUXANDMANYOFITSUSERSARENOTAWARETHATITISBASICALLYTHEGNUSYSTEMDEVELOPEDBYTHEGNUPROJECTTHEREREALLYISALINUXANDTHESEPEOPLEAREUSINGITBUTITISJUSTAPARTOFTHESYSTEMTHEYUSELINUXISTHEKERNELTHEPROGRAMINTHESYSTEMTHATALLOCATESTHEMACHINESRESOURCESTOTHEOTHERPROGRAMSTHATYOURUNTHEKERNELISANESSENTIALPARTOFANOPERATINGSYSTEMBUTUSELESSBYITSELFITCANONLYFUNCTIONINTHECONTEXTOFACOMPLETEOPERATINGSYSTEMLINUXISNORMALLYUSEDINCOMBINATIONWITHTHEGNUOPERATINGSYSTEMTHEWHOLESYSTEMISBASICALLYGNUWITHLINUXADDEDORGNULINUXALLTHESOCALLEDLINUXDISTRIBUTIONSAREREALLYDISTRIBUTIONSOFGNULINUXANYWAYHERECOMESTHEFLAGITSEVERYTHINGAFTERTHISATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS
# Flag: corctf{ATLEASTITSNOTAGENERICROTTHIRTEENCHALLENGEIGUESS}
