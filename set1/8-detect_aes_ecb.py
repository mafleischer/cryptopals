#!/usr/bin/python3

from crypto_algos.helpers import stateGenerator
import binascii

"""
detect AES in ECB mode
"""

if __name__ == "__main__":
	f = open("8.txt", "r")
	fcontent = f.read().split("\n")
	f.close()

	# keep track of cipher states that appear this many times
	threshold = 2

	bstr_list = []
	for hexstr in fcontent:
		bstr_list.append(binascii.a2b_hex(hexstr))

	# count number of times each state appears
	bstrs_w_highest_state_count = dict()
	for bstr in bstr_list:
		state_iter = stateGenerator(bstr)
		state_list = [state for state in state_iter]
		maxcount = 0
		state_counts = dict()
		for state in state_list:
			# more efficient
			if state not in state_counts:
				state_counts[state] = 1
			else:
				state_counts[state] += 1
		maxkey = max(state_counts.keys(), key=(lambda k: state_counts[k]))
		if state_counts[maxkey] >= threshold:
			bstrs_w_highest_state_count[bstr] = state_counts[maxkey]

			#count = state_list.count(state)
			#if count > maxcount:
			#	maxcount = count
		#if maxcount >= threshold:
		#	bstrs_w_highest_state_count[bstr] = maxcount

	print(bstrs_w_highest_state_count)