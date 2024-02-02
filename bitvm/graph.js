import {
	TraceResponse, 
	TraceResponseTimeout, 
	TraceChallenge,
	TraceChallengeTimeout
} from './trace.js'
import {
	CommitInstruction,
	CommitInstructionTimeout,
	DisproveProgram,
	ChallengeValueA,
	ChallengeValueB,
	ChallengeValueC,
	ChallengePcCurr,
	EquivocatedPcCurr,
	EquivocatedPcCurrTimeout,
	ChallengePcNext,
	EquivocatedPcNext,
	EquivocatedPcNextTimeout,
	ChallengeInstructionTimeout,
	KickOff
} from './bitvm.js'
import {
	MerkleResponseA, 
	MerkleResponseATimeout, 
	MerkleChallengeA,
	MerkleChallengeATimeout,
	MerkleResponseB, 
	MerkleResponseBTimeout, 
	MerkleChallengeB,
	MerkleChallengeBTimeout,
	MerkleHashA,
	MerkleHashB,
	MerkleHashTimeoutA,
	MerkleHashTimeoutB,
	MerkleEquivocationA,
	MerkleEquivocationB,
	MerkleEquivocationTimeoutA,
	MerkleEquivocationTimeoutB
} from './merkle/read.js'
import {
	MERKLE_WRITE_GRAPH
} from './merkle/write-graph.js'


class TraceResponse0 extends TraceResponse{ static INDEX = 0 }
class TraceResponse1 extends TraceResponse{ static INDEX = 1 }
class TraceResponse2 extends TraceResponse{ static INDEX = 2 }
class TraceResponse3 extends TraceResponse{ static INDEX = 3 }
class TraceResponse4 extends TraceResponse{ static INDEX = 4 }
class TraceResponse5 extends TraceResponse{ static INDEX = 5 }
class TraceResponse6 extends TraceResponse{ static INDEX = 6 }
class TraceResponse7 extends TraceResponse{ static INDEX = 7 }
class TraceResponse8 extends TraceResponse{ static INDEX = 8 }
class TraceResponse9 extends TraceResponse{ static INDEX = 9 }
class TraceResponse10 extends TraceResponse{ static INDEX = 10 }
class TraceResponse11 extends TraceResponse{ static INDEX = 11 }
class TraceResponse12 extends TraceResponse{ static INDEX = 12 }
class TraceResponse13 extends TraceResponse{ static INDEX = 13 }
class TraceResponse14 extends TraceResponse{ static INDEX = 14 }
class TraceResponse15 extends TraceResponse{ static INDEX = 15 }
class TraceResponse16 extends TraceResponse{ static INDEX = 16 }
class TraceResponse17 extends TraceResponse{ static INDEX = 17 }
class TraceResponse18 extends TraceResponse{ static INDEX = 18 }
class TraceResponse19 extends TraceResponse{ static INDEX = 19 }
class TraceResponse20 extends TraceResponse{ static INDEX = 20 }
class TraceResponse21 extends TraceResponse{ static INDEX = 21 }
class TraceResponse22 extends TraceResponse{ static INDEX = 22 }
class TraceResponse23 extends TraceResponse{ static INDEX = 23 }
class TraceResponse24 extends TraceResponse{ static INDEX = 24 }
class TraceResponse25 extends TraceResponse{ static INDEX = 25 }
class TraceResponse26 extends TraceResponse{ static INDEX = 26 }
class TraceResponse27 extends TraceResponse{ static INDEX = 27 }
class TraceResponse28 extends TraceResponse{ static INDEX = 28 }
class TraceResponse29 extends TraceResponse{ static INDEX = 29 }
class TraceResponse30 extends TraceResponse{ static INDEX = 30 }
class TraceResponse31 extends TraceResponse{ static INDEX = 31 }


class TraceResponseTimeout0 extends TraceResponseTimeout{}
class TraceResponseTimeout1 extends TraceResponseTimeout{}
class TraceResponseTimeout2 extends TraceResponseTimeout{}
class TraceResponseTimeout3 extends TraceResponseTimeout{}
class TraceResponseTimeout4 extends TraceResponseTimeout{}
class TraceResponseTimeout5 extends TraceResponseTimeout{}
class TraceResponseTimeout6 extends TraceResponseTimeout{}
class TraceResponseTimeout7 extends TraceResponseTimeout{}
class TraceResponseTimeout8 extends TraceResponseTimeout{}
class TraceResponseTimeout9 extends TraceResponseTimeout{}
class TraceResponseTimeout10 extends TraceResponseTimeout{}
class TraceResponseTimeout11 extends TraceResponseTimeout{}
class TraceResponseTimeout12 extends TraceResponseTimeout{}
class TraceResponseTimeout13 extends TraceResponseTimeout{}
class TraceResponseTimeout14 extends TraceResponseTimeout{}
class TraceResponseTimeout15 extends TraceResponseTimeout{}
class TraceResponseTimeout16 extends TraceResponseTimeout{}
class TraceResponseTimeout17 extends TraceResponseTimeout{}
class TraceResponseTimeout18 extends TraceResponseTimeout{}
class TraceResponseTimeout19 extends TraceResponseTimeout{}
class TraceResponseTimeout20 extends TraceResponseTimeout{}
class TraceResponseTimeout21 extends TraceResponseTimeout{}
class TraceResponseTimeout22 extends TraceResponseTimeout{}
class TraceResponseTimeout23 extends TraceResponseTimeout{}
class TraceResponseTimeout24 extends TraceResponseTimeout{}
class TraceResponseTimeout25 extends TraceResponseTimeout{}
class TraceResponseTimeout26 extends TraceResponseTimeout{}
class TraceResponseTimeout27 extends TraceResponseTimeout{}
class TraceResponseTimeout28 extends TraceResponseTimeout{}
class TraceResponseTimeout29 extends TraceResponseTimeout{}
class TraceResponseTimeout30 extends TraceResponseTimeout{}
class TraceResponseTimeout31 extends TraceResponseTimeout{}


class TraceChallenge0 extends TraceChallenge{ static INDEX = 0} 
class TraceChallenge1 extends TraceChallenge{ static INDEX = 1} 
class TraceChallenge2 extends TraceChallenge{ static INDEX = 2} 
class TraceChallenge3 extends TraceChallenge{ static INDEX = 3} 
class TraceChallenge4 extends TraceChallenge{ static INDEX = 4} 
class TraceChallenge5 extends TraceChallenge{ static INDEX = 5} 
class TraceChallenge6 extends TraceChallenge{ static INDEX = 6} 
class TraceChallenge7 extends TraceChallenge{ static INDEX = 7} 
class TraceChallenge8 extends TraceChallenge{ static INDEX = 8} 
class TraceChallenge9 extends TraceChallenge{ static INDEX = 9} 
class TraceChallenge10 extends TraceChallenge{ static INDEX = 10} 
class TraceChallenge11 extends TraceChallenge{ static INDEX = 11} 
class TraceChallenge12 extends TraceChallenge{ static INDEX = 12} 
class TraceChallenge13 extends TraceChallenge{ static INDEX = 13} 
class TraceChallenge14 extends TraceChallenge{ static INDEX = 14} 
class TraceChallenge15 extends TraceChallenge{ static INDEX = 15} 
class TraceChallenge16 extends TraceChallenge{ static INDEX = 16} 
class TraceChallenge17 extends TraceChallenge{ static INDEX = 17} 
class TraceChallenge18 extends TraceChallenge{ static INDEX = 18} 
class TraceChallenge19 extends TraceChallenge{ static INDEX = 19} 
class TraceChallenge20 extends TraceChallenge{ static INDEX = 20} 
class TraceChallenge21 extends TraceChallenge{ static INDEX = 21} 
class TraceChallenge22 extends TraceChallenge{ static INDEX = 22} 
class TraceChallenge23 extends TraceChallenge{ static INDEX = 23} 
class TraceChallenge24 extends TraceChallenge{ static INDEX = 24} 
class TraceChallenge25 extends TraceChallenge{ static INDEX = 25} 
class TraceChallenge26 extends TraceChallenge{ static INDEX = 26} 
class TraceChallenge27 extends TraceChallenge{ static INDEX = 27} 
class TraceChallenge28 extends TraceChallenge{ static INDEX = 28} 
class TraceChallenge29 extends TraceChallenge{ static INDEX = 29} 
class TraceChallenge30 extends TraceChallenge{ static INDEX = 30} 
class TraceChallenge31 extends TraceChallenge{ static INDEX = 31} 


class TraceChallengeTimeout0 extends TraceChallengeTimeout{}
class TraceChallengeTimeout1 extends TraceChallengeTimeout{}
class TraceChallengeTimeout2 extends TraceChallengeTimeout{}
class TraceChallengeTimeout3 extends TraceChallengeTimeout{}
class TraceChallengeTimeout4 extends TraceChallengeTimeout{}
class TraceChallengeTimeout5 extends TraceChallengeTimeout{}
class TraceChallengeTimeout6 extends TraceChallengeTimeout{}
class TraceChallengeTimeout7 extends TraceChallengeTimeout{}
class TraceChallengeTimeout8 extends TraceChallengeTimeout{}
class TraceChallengeTimeout9 extends TraceChallengeTimeout{}
class TraceChallengeTimeout10 extends TraceChallengeTimeout{}
class TraceChallengeTimeout11 extends TraceChallengeTimeout{}
class TraceChallengeTimeout12 extends TraceChallengeTimeout{}
class TraceChallengeTimeout13 extends TraceChallengeTimeout{}
class TraceChallengeTimeout14 extends TraceChallengeTimeout{}
class TraceChallengeTimeout15 extends TraceChallengeTimeout{}
class TraceChallengeTimeout16 extends TraceChallengeTimeout{}
class TraceChallengeTimeout17 extends TraceChallengeTimeout{}
class TraceChallengeTimeout18 extends TraceChallengeTimeout{}
class TraceChallengeTimeout19 extends TraceChallengeTimeout{}
class TraceChallengeTimeout20 extends TraceChallengeTimeout{}
class TraceChallengeTimeout21 extends TraceChallengeTimeout{}
class TraceChallengeTimeout22 extends TraceChallengeTimeout{}
class TraceChallengeTimeout23 extends TraceChallengeTimeout{}
class TraceChallengeTimeout24 extends TraceChallengeTimeout{}
class TraceChallengeTimeout25 extends TraceChallengeTimeout{}
class TraceChallengeTimeout26 extends TraceChallengeTimeout{}
class TraceChallengeTimeout27 extends TraceChallengeTimeout{}
class TraceChallengeTimeout28 extends TraceChallengeTimeout{}
class TraceChallengeTimeout29 extends TraceChallengeTimeout{}
class TraceChallengeTimeout30 extends TraceChallengeTimeout{}
class TraceChallengeTimeout31 extends TraceChallengeTimeout{}


class MerkleChallengeA0 extends MerkleChallengeA{ static INDEX = 0 }
class MerkleChallengeA1 extends MerkleChallengeA{ static INDEX = 1 }
class MerkleChallengeA2 extends MerkleChallengeA{ static INDEX = 2 }
class MerkleChallengeA3 extends MerkleChallengeA{ static INDEX = 3 }
class MerkleChallengeA4 extends MerkleChallengeA{ static INDEX = 4 }

class MerkleChallengeTimeoutA0 extends MerkleChallengeATimeout{}
class MerkleChallengeTimeoutA1 extends MerkleChallengeATimeout{}
class MerkleChallengeTimeoutA2 extends MerkleChallengeATimeout{}
class MerkleChallengeTimeoutA3 extends MerkleChallengeATimeout{}
class MerkleChallengeTimeoutA4 extends MerkleChallengeATimeout{}

class MerkleResponseA0 extends MerkleResponseA{ static INDEX = 0 }
class MerkleResponseA1 extends MerkleResponseA{ static INDEX = 1 }
class MerkleResponseA2 extends MerkleResponseA{ static INDEX = 2 }
class MerkleResponseA3 extends MerkleResponseA{ static INDEX = 3 }
class MerkleResponseA4 extends MerkleResponseA{ static INDEX = 4 }

class MerkleResponseTimeoutA0 extends MerkleResponseATimeout{}
class MerkleResponseTimeoutA1 extends MerkleResponseATimeout{}
class MerkleResponseTimeoutA2 extends MerkleResponseATimeout{}
class MerkleResponseTimeoutA3 extends MerkleResponseATimeout{}
class MerkleResponseTimeoutA4 extends MerkleResponseATimeout{}



class MerkleChallengeB0 extends MerkleChallengeB{ static INDEX = 0 }
class MerkleChallengeB1 extends MerkleChallengeB{ static INDEX = 1 }
class MerkleChallengeB2 extends MerkleChallengeB{ static INDEX = 2 }
class MerkleChallengeB3 extends MerkleChallengeB{ static INDEX = 3 }
class MerkleChallengeB4 extends MerkleChallengeB{ static INDEX = 4 }

class MerkleChallengeTimeoutB0 extends MerkleChallengeBTimeout{}
class MerkleChallengeTimeoutB1 extends MerkleChallengeBTimeout{}
class MerkleChallengeTimeoutB2 extends MerkleChallengeBTimeout{}
class MerkleChallengeTimeoutB3 extends MerkleChallengeBTimeout{}
class MerkleChallengeTimeoutB4 extends MerkleChallengeBTimeout{}

class MerkleResponseB0 extends MerkleResponseB{ static INDEX = 0 }
class MerkleResponseB1 extends MerkleResponseB{ static INDEX = 1 }
class MerkleResponseB2 extends MerkleResponseB{ static INDEX = 2 }
class MerkleResponseB3 extends MerkleResponseB{ static INDEX = 3 }
class MerkleResponseB4 extends MerkleResponseB{ static INDEX = 4 }

class MerkleResponseTimeoutB0 extends MerkleResponseBTimeout{}
class MerkleResponseTimeoutB1 extends MerkleResponseBTimeout{}
class MerkleResponseTimeoutB2 extends MerkleResponseBTimeout{}
class MerkleResponseTimeoutB3 extends MerkleResponseBTimeout{}
class MerkleResponseTimeoutB4 extends MerkleResponseBTimeout{}




export const BITVM_GRAPH = {
	START : [ KickOff ],

	KickOff 		  : [ TraceResponse0,   TraceResponseTimeout0  ],
	TraceResponse0    : [ TraceChallenge0,  TraceChallengeTimeout0 ],
	TraceChallenge0   : [ TraceResponse1,   TraceResponseTimeout1  ],
	TraceResponse1    : [ TraceChallenge1,  TraceChallengeTimeout1 ],
	TraceChallenge1   : [ TraceResponse2,   TraceResponseTimeout2  ],
	TraceResponse2    : [ TraceChallenge2,  TraceChallengeTimeout2 ],
	TraceChallenge2   : [ TraceResponse3,   TraceResponseTimeout3  ],
	TraceResponse3    : [ TraceChallenge3,  TraceChallengeTimeout3 ],
	// TraceChallenge3   : [ TraceResponse4,   TraceResponseTimeout4  ],
	// TraceResponse4    : [ TraceChallenge4,  TraceChallengeTimeout4 ],
	// TraceChallenge4   : [ TraceResponse5,   TraceResponseTimeout5  ],
	// TraceResponse5    : [ TraceChallenge5,  TraceChallengeTimeout5 ],
	// TraceChallenge5   : [ TraceResponse6,   TraceResponseTimeout6  ],
	// TraceResponse6    : [ TraceChallenge6,  TraceChallengeTimeout6 ],
	// TraceChallenge6   : [ TraceResponse7,   TraceResponseTimeout7  ],
	// TraceResponse7    : [ TraceChallenge7,  TraceChallengeTimeout7 ],
	// TraceChallenge7   : [ TraceResponse8,   TraceResponseTimeout8  ],
	// TraceResponse8    : [ TraceChallenge8,  TraceChallengeTimeout8 ],
	// TraceChallenge8   : [ TraceResponse9,   TraceResponseTimeout9  ],
	// TraceResponse9    : [ TraceChallenge9,  TraceChallengeTimeout9 ],
	// TraceChallenge9   : [ TraceResponse10,  TraceResponseTimeout10  ],
	// TraceResponse10   : [ TraceChallenge10, TraceChallengeTimeout10 ],
	// TraceChallenge10  : [ TraceResponse11,  TraceResponseTimeout11  ],
	// TraceResponse11   : [ TraceChallenge11, TraceChallengeTimeout11 ],
	// TraceChallenge11  : [ TraceResponse12,  TraceResponseTimeout12  ],
	// TraceResponse12   : [ TraceChallenge12, TraceChallengeTimeout12 ],
	// TraceChallenge12  : [ TraceResponse13,  TraceResponseTimeout13  ],
	// TraceResponse13   : [ TraceChallenge13, TraceChallengeTimeout13 ],
	// TraceChallenge13  : [ TraceResponse14,  TraceResponseTimeout14  ],
	// TraceResponse14   : [ TraceChallenge14, TraceChallengeTimeout14 ],
	// TraceChallenge14  : [ TraceResponse15,  TraceResponseTimeout15  ],
	// TraceResponse15   : [ TraceChallenge15, TraceChallengeTimeout15 ],
	// TraceChallenge15  : [ TraceResponse16,  TraceResponseTimeout16  ],
	// TraceResponse16   : [ TraceChallenge16, TraceChallengeTimeout16 ],
	// TraceChallenge16  : [ TraceResponse17,  TraceResponseTimeout17  ],
	// TraceResponse17   : [ TraceChallenge17, TraceChallengeTimeout17 ],
	// TraceChallenge17  : [ TraceResponse18,  TraceResponseTimeout18  ],
	// TraceResponse18   : [ TraceChallenge18, TraceChallengeTimeout18 ],
	// TraceChallenge18  : [ TraceResponse19,  TraceResponseTimeout19  ],
	// TraceResponse19   : [ TraceChallenge19, TraceChallengeTimeout19 ],
	// TraceChallenge19  : [ TraceResponse20,  TraceResponseTimeout20  ],
	// TraceResponse20   : [ TraceChallenge20, TraceChallengeTimeout20 ],
	// TraceChallenge20  : [ TraceResponse21,  TraceResponseTimeout21  ],
	// TraceResponse21   : [ TraceChallenge21, TraceChallengeTimeout21 ],
	// TraceChallenge21  : [ TraceResponse22,  TraceResponseTimeout22  ],
	// TraceResponse22   : [ TraceChallenge22, TraceChallengeTimeout22 ],
	// TraceChallenge22  : [ TraceResponse23,  TraceResponseTimeout23  ],
	// TraceResponse23   : [ TraceChallenge23, TraceChallengeTimeout23 ],
	// TraceChallenge23  : [ TraceResponse24,  TraceResponseTimeout24  ],
	// TraceResponse24   : [ TraceChallenge24, TraceChallengeTimeout24 ],
	// TraceChallenge24  : [ TraceResponse25,  TraceResponseTimeout25  ],
	// TraceResponse25   : [ TraceChallenge25, TraceChallengeTimeout25 ],
	// TraceChallenge25  : [ TraceResponse26,  TraceResponseTimeout26  ],
	// TraceResponse26   : [ TraceChallenge26, TraceChallengeTimeout26 ],
	// TraceChallenge26  : [ TraceResponse27,  TraceResponseTimeout27  ],
	// TraceResponse27   : [ TraceChallenge27, TraceChallengeTimeout27 ],
	// TraceChallenge27  : [ TraceResponse28,  TraceResponseTimeout28  ],
	// TraceResponse28   : [ TraceChallenge28, TraceChallengeTimeout28 ],
	// TraceChallenge28  : [ TraceResponse29,  TraceResponseTimeout29  ],
	// TraceResponse29   : [ TraceChallenge29, TraceChallengeTimeout29 ],
	// TraceChallenge29  : [ TraceResponse30,  TraceResponseTimeout30  ],
	// TraceResponse30   : [ TraceChallenge30, TraceChallengeTimeout30 ],
	// TraceChallenge30  : [ TraceResponse31,  TraceResponseTimeout31  ],
	// TraceResponse31   : [ TraceChallenge31, TraceChallengeTimeout31 ],
	// TraceChallenge31  : [ CommitInstruction, CommitInstructionTimeout ],
	TraceChallenge3  : [ CommitInstruction, CommitInstructionTimeout ],
	
	CommitInstruction : [ 
							DisproveProgram,
							ChallengePcCurr,
							ChallengePcNext,
							ChallengeValueA,
							ChallengeValueB,
							ChallengeValueC,
							ChallengeInstructionTimeout,
						],

	ChallengePcCurr : [ EquivocatedPcCurr, EquivocatedPcCurrTimeout ],
	ChallengePcNext : [ EquivocatedPcNext, EquivocatedPcNextTimeout ],

	ChallengeValueA   : [ MerkleResponseA0, MerkleResponseTimeoutA0 ],
	MerkleResponseA0  : [ MerkleChallengeA0, MerkleChallengeTimeoutA0 ],
	MerkleChallengeA0 : [ MerkleResponseA1,  MerkleResponseTimeoutA1  ],
	MerkleResponseA1  : [ MerkleChallengeA1, MerkleChallengeTimeoutA1 ],
	MerkleChallengeA1 : [ MerkleResponseA2,  MerkleResponseTimeoutA2  ],
	MerkleResponseA2  : [ MerkleChallengeA2, MerkleChallengeTimeoutA2 ],
	MerkleChallengeA2 : [ MerkleResponseA3,  MerkleResponseTimeoutA3  ],
	MerkleResponseA3  : [ MerkleChallengeA3, MerkleChallengeTimeoutA3 ],
	MerkleChallengeA3 : [ MerkleResponseA4,  MerkleResponseTimeoutA4  ],
	MerkleResponseA4  : [ MerkleChallengeA4, MerkleChallengeTimeoutA4 ],
	MerkleChallengeA4 : [ MerkleHashA, MerkleHashTimeoutA ],
	MerkleHashA : [ MerkleEquivocationA, MerkleEquivocationTimeoutA ],


	ChallengeValueB   : [ MerkleResponseB0, MerkleResponseTimeoutB0 ],
	MerkleResponseB0  : [ MerkleChallengeB0, MerkleChallengeTimeoutB0 ],
	MerkleChallengeB0 : [ MerkleResponseB1,  MerkleResponseTimeoutB1  ],
	MerkleResponseB1  : [ MerkleChallengeB1, MerkleChallengeTimeoutB1 ],
	MerkleChallengeB1 : [ MerkleResponseB2,  MerkleResponseTimeoutB2  ],
	MerkleResponseB2  : [ MerkleChallengeB2, MerkleChallengeTimeoutB2 ],
	MerkleChallengeB2 : [ MerkleResponseB3,  MerkleResponseTimeoutB3  ],
	MerkleResponseB3  : [ MerkleChallengeB3, MerkleChallengeTimeoutB3 ],
	MerkleChallengeB3 : [ MerkleResponseB4,  MerkleResponseTimeoutB4  ],
	MerkleResponseB4  : [ MerkleChallengeB4, MerkleChallengeTimeoutB4 ],
	MerkleChallengeB4 : [ MerkleHashB, MerkleHashTimeoutB ],
	MerkleHashB : [ MerkleEquivocationB, MerkleEquivocationTimeoutB ],
	
}


Object.assign(BITVM_GRAPH, MERKLE_WRITE_GRAPH)
