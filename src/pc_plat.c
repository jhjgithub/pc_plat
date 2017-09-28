/*
 *     Filename: pc_plat.c
 *  Description: Source file for packet classification platform
 *
 *       Author: Xiang Wang (xiang.wang.s@gmail.com)
 *
 * Organization: Network Security Laboratory (NSLab),
 *               Research Institute of Information Technology (RIIT),
 *               Tsinghua University (THU)
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "common/rule_trace.h"
#include "clsfy/hypersplit.h"
#include "group/rfg.h"

#define GRP_FILE "group_result.txt"


enum {
	RULE_FMT_INV		= -1,
	RULE_FMT_WUSTL		= 0,
	RULE_FMT_WUSTL_G	= 1,
	RULE_FMT_MAX		= 2
};

enum {
	PC_ALGO_INV			= -1,
	PC_ALGO_HYPERSPLIT	= 0,
	PC_ALGO_MAX			= 1
};

enum {
	GRP_ALGO_INV	= -1,
	GRP_ALGO_RFG	= 0,
	GRP_ALGO_MAX	= 1
};


struct platform_config {
	char	*s_rule_file;
	char	*s_trace_file;
	int		rule_fmt;
	int		pc_algo;
	int		grp_algo;
};


static void print_help(void)
{
	const char *s_help =
		"NSLab Packet Classification Platform\n"
		"\n"
		"Valid options:\n"
		"  -r, --rule FILE  specify a rule file for building\n"
		"  -f, --format FORMAT  specify a rule file format: [wustl, wustl_g]\n"
		"  -t, --trace FILE  specify a trace file for searching\n"
		"\n"
		"  -p, --pc ALGO  specify a pc algorithm: [hs]\n"
		"  -g, --grp ALGO  specify a grp algorithm: [rfg]\n"
		"\n"
		"  -h, --help  display this help and exit\n"
		"\n";

	fprintf(stdout, "%s", s_help);

	return;
}

static void parse_args(struct platform_config *plat_cfg, int argc, char *argv[])
{
	int option;
	const char *s_opts = "r:f:t:p:g:h";
	const struct option opts[] = {
		{ "rule",	required_argument, NULL, 'r' },
		{ "format", required_argument, NULL, 'f' },
		{ "trace",	required_argument, NULL, 't' },
		{ "pc",		required_argument, NULL, 'p' },
		{ "grp",	required_argument, NULL, 'g' },
		{ "help",	no_argument,	   NULL, 'h' },
		{ NULL,		0,				   NULL, 0	 }
	};

	assert(plat_cfg && argv);

	if (argc < 2) {
		print_help();
		exit(-1);
	}

	while ((option = getopt_long(argc, argv, s_opts, opts, NULL)) != -1) {
		switch (option) {
		case 'r':
		case 't':
			if (access(optarg, F_OK) == -1) {
				perror(optarg);
				exit(-1);
			}

			if (option == 'r') {
				plat_cfg->s_rule_file = optarg;
			}
			else if (option == 't') {
				plat_cfg->s_trace_file = optarg;
			}

			break;

		case 'f':
			if (!strcmp(optarg, "wustl")) {
				plat_cfg->rule_fmt = RULE_FMT_WUSTL;
			}
			else if (!strcmp(optarg, "wustl_g")) {
				plat_cfg->rule_fmt = RULE_FMT_WUSTL_G;
			}

			break;

		case 'p':
			if (!strcmp(optarg, "hs")) {
				plat_cfg->pc_algo = PC_ALGO_HYPERSPLIT;
			}

			break;

		case 'g':
			if (!strcmp(optarg, "rfg")) {
				plat_cfg->grp_algo = GRP_ALGO_RFG;
			}

			break;

		case 'h':
			print_help();
			exit(0);

		default:
			print_help();
			exit(-1);
		}
	}

	if (!plat_cfg->s_rule_file) {
		fprintf(stderr, "Not specify the rule file\n");
		exit(-1);
	}

	if (plat_cfg->rule_fmt == RULE_FMT_INV) {
		fprintf(stderr, "Not specify the rule format\n");
		exit(-1);
	}

	if (plat_cfg->pc_algo != PC_ALGO_INV &&
		plat_cfg->grp_algo != GRP_ALGO_INV) {
		fprintf(stderr, "Cannot run in hybrid mode [pc & grp]\n");
		exit(-1);
	}
	else if (plat_cfg->pc_algo != PC_ALGO_INV) {
		fprintf(stderr, "Run in pc mode\n");
	}
	else if (plat_cfg->grp_algo != GRP_ALGO_INV) {
		fprintf(stderr, "Run in grp mode\n");
	}
	else {
		fprintf(stderr, "Not specify the pc or grp algorithm\n");
		exit(-1);
	}

	return;
}

static uint64_t make_timediff(const struct timespec	stop,
								const struct timespec	start)
{
	return (stop.tv_sec * 1000000ULL + stop.tv_nsec / 1000)
		   - (start.tv_sec * 1000000ULL + start.tv_nsec / 1000);
}

#if 0
static int f_build(int pc_algo, void *built_result,
				   const struct partition *p_pa)
{
	assert(pc_algo > PC_ALGO_INV && pc_algo < PC_ALGO_MAX);
	assert(built_result && p_pa && p_pa->subsets && p_pa->rule_num > 1);
	assert(p_pa->subset_num > 0 && p_pa->subset_num <= PART_MAX);

	switch (pc_algo) {
	case PC_ALGO_HYPERSPLIT:
		return hs_build(built_result, p_pa);

	default:
		*(typeof(built_result) *)built_result = NULL;
		return -ENOTSUP;
	}
}

static int f_group(int grp_algo, struct partition *p_pa_grp,
				   const struct partition *p_pa)
{
	assert(grp_algo > GRP_ALGO_INV && grp_algo < GRP_ALGO_MAX);
	assert(p_pa_grp && p_pa && p_pa->subsets && p_pa->rule_num > 1);
	assert(p_pa->subset_num > 0 && p_pa->subset_num <= PART_MAX);

	switch (grp_algo) {
	case GRP_ALGO_RFG:
		return rf_group(p_pa_grp, p_pa);

	default:
		return -ENOTSUP;
	}
}

static int f_search(int pc_algo, const struct trace *p_t,
					const void *built_result)
{
	assert(pc_algo > PC_ALGO_INV && pc_algo < PC_ALGO_MAX);
	assert(p_t && p_t->pkts && built_result);

	if (*(typeof(built_result) *)built_result == NULL) {
		return -EINVAL;
	}

	switch (pc_algo) {
	case PC_ALGO_HYPERSPLIT:
		return hs_search(p_t, built_result);

	default:
		return -ENOTSUP;
	}
}

static void f_destroy(int pc_algo, void *built_result)
{
	assert(pc_algo > PC_ALGO_INV && pc_algo < PC_ALGO_MAX);
	assert(built_result);

	if (*(typeof(built_result) *)built_result == NULL) {
		return;
	}

	switch (pc_algo) {
	case PC_ALGO_HYPERSPLIT:
		hs_destroy(built_result);
		break;

	default:
		break;
	}

	*(typeof(built_result) *)built_result = NULL;

	return;
}

#endif

size_t hs_tree_memory_size(void *hypersplit, uint32_t *total_node)
{
	const struct hs_result *hsret;
	size_t tmem = 0;
	uint32_t nodes = 0;

	hsret = (const struct hs_result*)hypersplit;
	if (!hsret || !hsret->trees) {
		return 0;
	}

	int j;

	for (j = 0; j < hsret->tree_num; j++) {
		struct hs_tree *t = &hsret->trees[j];

		tmem += (t->inode_num * sizeof(struct hs_node));
		tmem += (t->enode_num * sizeof(struct hs_node));

		nodes += t->inode_num;
		nodes += t->enode_num;
	}

	if (total_node) {
		*total_node = nodes;
	}

	return tmem;
}

void save_hypersplit(void *hs)
{
	int fd;
	const struct hs_result *hsret;
	hsret = (const struct hs_result*)hs;
	
	fd = open("hs.bin", O_WRONLY | O_TRUNC, 0644);

	if (fd == -1) {
		printf("cannot open hs.bin \n");
		return;
	}

	ssize_t l;

	l = write(fd, &hsret->tree_num, sizeof(int));
	l = write(fd, &hsret->def_rule, sizeof(int));

	int j;

	for (j = 0; j < hsret->tree_num; j++) {
		struct hs_tree *t = &hsret->trees[j];

		l = write(fd, &t->inode_num, sizeof(int));
		l = write(fd, &t->enode_num, sizeof(int));
		l = write(fd, &t->depth_max, sizeof(int));
	}


}


int main(int argc, char *argv[])
{
	struct timespec starttime, stoptime;
	uint64_t timediff;

	struct partition pa, pa_grp;
	struct trace t;
	void *result = NULL;

	struct platform_config plat_cfg = {
		.s_rule_file	= NULL,
		.s_trace_file	= NULL,
		.rule_fmt		= RULE_FMT_INV,
		.pc_algo		= PC_ALGO_INV,
		.grp_algo		= GRP_ALGO_INV
	};

	parse_args(&plat_cfg, argc, argv);

	/*
	 * Loading classifier
	 */
	if (plat_cfg.rule_fmt == RULE_FMT_WUSTL) {
		pa.subsets = calloc(1, sizeof(*pa.subsets));
		if (!pa.subsets) {
			perror("Cannot allocate memory for subsets");
			exit(-1);
		}

		if (load_rules(pa.subsets, plat_cfg.s_rule_file)) {
			exit(-1);
		}

		pa.subset_num = 1;
		pa.rule_num = pa.subsets[0].rule_num;

		// grouping
		printf("Grouping ... \n");
		fflush(NULL);

		if (pa.rule_num > 2) {
			if (rf_group(&pa_grp, &pa)) {
				printf("Error Grouping ... \n");
				exit(-1);
			}

			unload_partition(&pa);

			pa.subset_num = pa_grp.subset_num;
			pa.rule_num = pa_grp.rule_num;
			pa.subsets = pa_grp.subsets;

			pa_grp.subset_num = 0;
			pa_grp.rule_num = 0;
			pa_grp.subsets = NULL;
			unload_partition(&pa_grp);

			printf("subset_num=%d, rule=%d \n", pa.subset_num, pa.rule_num);
			fflush(NULL);
		}

#if 0
		printf("Saving  ... \n");
		fflush(NULL);
		dump_partition(GRP_FILE, &pa_grp);

		printf("Loading ... \n");
		fflush(NULL);

		if (load_partition(&pa, GRP_FILE)) {
			exit(-1);
		}

		printf("pa: subset_num=%d, rule=%d \n",
			   pa.subset_num, pa.rule_num);

		fflush(NULL);
#endif
	}
	else if (plat_cfg.rule_fmt == RULE_FMT_WUSTL_G) {
		if (load_partition(&pa, plat_cfg.s_rule_file)) {
			exit(-1);
		}

		if (plat_cfg.grp_algo != GRP_ALGO_INV) {
			printf("Reverting ... \n");
			fflush(NULL);

			struct rule_set *p_rs = calloc(1, sizeof(*p_rs));
			if (!p_rs) {
				perror("Cannot allocate memory for subsets");
				exit(-1);
			}

			if (revert_partition(p_rs, &pa)) {
				exit(-1);
			}

			unload_partition(&pa);

			pa.subsets = p_rs;
			pa.subset_num = 1;
			pa.rule_num = pa.subsets[0].rule_num;
		}
	}

	/*
	 * Grouping
	 */
	if (plat_cfg.grp_algo != GRP_ALGO_INV) {
		fprintf(stderr, "Grouping\n");

		clock_gettime(CLOCK_MONOTONIC, &starttime);

		assert(pa.subset_num == 1);

		if (rf_group(&pa_grp, &pa)) {
			fprintf(stderr, "Grouping fail\n");
			exit(-1);
		}

		clock_gettime(CLOCK_MONOTONIC, &stoptime);

		fprintf(stderr, "Grouping pass\n");
		fprintf(stderr, "Time for grouping: %" PRIu64 "(us)\n",
				make_timediff(stoptime, starttime));

		dump_partition(GRP_FILE, &pa_grp);

		unload_partition(&pa_grp);
		unload_partition(&pa);

		return 0;
	}

	/*
	 * Building
	 */
	fprintf(stderr, "Building\n");

	clock_gettime(CLOCK_MONOTONIC, &starttime);

	//call hs_build()
	if (hs_build(&result, &pa)) {
		fprintf(stderr, "Building fail\n");
		exit(-1);
	}

	clock_gettime(CLOCK_MONOTONIC, &stoptime);

	fprintf(stderr, "Building pass\n");
	fprintf(stderr, "Time for building: %" PRIu64 "(us)\n",
			make_timediff(stoptime, starttime));

	unload_partition(&pa);

	if (!plat_cfg.s_trace_file) {
		hs_destroy(&result);
		return 0;
	}
	else if (load_trace(&t, plat_cfg.s_trace_file)) {
		exit(-1);
	}

	/*
	 * Searching
	 */
	fprintf(stderr, "Searching\n");

	clock_gettime(CLOCK_MONOTONIC, &starttime);

	if (hs_search(&t, &result)) {
		//fprintf(stderr, "Searching fail\n");
		//exit(-1);
	}

	clock_gettime(CLOCK_MONOTONIC, &stoptime);
	timediff = make_timediff(stoptime, starttime);

	int i;
	for (i = 0; i < t.pkt_num; i++) {
		if (t.pkts[i].found != t.pkts[i].match_rule) {
			fprintf(stderr, "packet %d match %d, but should match %d\n",
					i, t.pkts[i].found, t.pkts[i].match_rule);
		}
	}

	fprintf(stderr, "Searching pass\n");
	fprintf(stderr, "Time for searching: %" PRIu64 "(us)\n", timediff);
	fprintf(stderr, "Searching speed: %lld(pps)\n",
			(t.pkt_num * 1000000ULL) / timediff);

	unload_trace(&t);

	hs_destroy(&result);

	return 0;
}
