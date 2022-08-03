#!/usr/bin/env python3

#
# This file is part of the plotting scripts supporting the CacheSC library
# (https://github.com/Miro-H/CacheSC), which implements Prime+Probe attacks on
# virtually and physically indexed caches.
#
# Copyright (C) 2020  Miro Haller
#
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <https://www.gnu.org/licenses/>.
#
# Contact: miro.haller@alumni.ethz.ch
#
# Short description of this file:
# Plots cache side-channel timing observations from a log file that has a certain
# structure (see parser.py or the log file generated by the demo code)
#

# Next to lines are to use matplotlib without X server (display)
import matplotlib as mpl
mpl.use('Agg')
import matplotlib.pyplot as plt
import argparse
import scipy.stats.mstats as stats
import numpy as np

from logger import Logger
from parser import Parser
import seaborn as sns


# Constants
TRIM_HIGH_PERCENTAGE    = 0.00
TRIM_LOW_PERCENTAGE     = 0


# Parse command line arguments
parser = argparse.ArgumentParser()
parser.add_argument("log_file", help="path to log file to parse")
parser.add_argument("-o", "--output_folder",
                    help="path to folder for the produced plots",
                    default="./plots")
parser.add_argument("--ylims", help="fix y axis of plot, tuple (y_min, y_max)",
                    default="tuple()")
parser.add_argument("-n", "--normalize", help="normalize samples using an additional "
                                              "data set with uninfluenced data points",
                    action="store_true")
parser.add_argument("-t", "--transpose", help="transpose data set, i.e. average over"
                                              "the i-th entries of each sample",
                    action="store_true")
parser.add_argument("-v", "--verbose", help="print debug output", action="store_true")

args = parser.parse_args()

log_file_path = args.log_file
output_folder = args.output_folder
y_lims        = eval(args.ylims)
do_normalize  = args.normalize
do_transpose  = args.transpose
verbose       = args.verbose

log_file_name = log_file_path
if "/" in log_file_path:
    log_file_name = log_file_name.rsplit("/", 1)[1]

logger = Logger("plot")
if verbose:
    logger.set_verbose()

logger.title("Start plotting")

# Parse log file
parser = Parser()
samples, bl_samples, meta_data = parser.parse(log_file_path, do_normalize)

logger.line(f"Compute statistics")

# Prepare data
def tmean(arr):
    #return np.mean(arr)
    return stats.trimmed_mean(arr, limits=(TRIM_LOW_PERCENTAGE, TRIM_HIGH_PERCENTAGE))

def tstd(arr):
    return stats.trimmed_std(arr, limits=(TRIM_LOW_PERCENTAGE, TRIM_HIGH_PERCENTAGE))

if do_transpose:
    samples = list(map(list, zip(*samples)))

trimmed_samples = stats.trim(samples, limits=(TRIM_LOW_PERCENTAGE, TRIM_HIGH_PERCENTAGE), axis=0, relative=True)

avg_per_entry   = np.mean(trimmed_samples,  axis=0)#list(map(tmean, samples))
std_per_entry   = np.std(trimmed_samples,  axis=0) #list(map(tstd, samples))
min_per_entry = np.amin(trimmed_samples, axis=0) #avg_per_entry-std_per_entry#np.amin(trimmed_samples, axis=0)
print(min_per_entry)
max_per_entry = np.amax(trimmed_samples, axis=0)#avg_per_entry+std_per_entry#np.amax(trimmed_samples, axis=0)
#print(max_per_entry)
overall_avg = stats.trimmed_mean(samples, limits=(TRIM_LOW_PERCENTAGE, TRIM_HIGH_PERCENTAGE))

#print("### Avg per entry sammler yero", avg_per_entry[avg_per_entry < 0 ])
#flatten_array = np.array(samples).flatten()
#print("### samples below zero", flatten_array[flatten_array < 0])
idx = 0
logger.debug(sorted(samples[idx]))
logger.debug(f"tmean: {tmean(samples[idx])}")

if do_normalize:
    logger.line("Normalize samples")
    if do_transpose:
        bl_samples = list(map(list, zip(*bl_samples)))
    avg_bl_per_entry = list(map(tmean, bl_samples))

    for i in range(len(avg_bl_per_entry)):
        avg_per_entry[i] -= avg_bl_per_entry[i]
    logger.debug(f"baseline: {avg_bl_per_entry[idx]}")
    logger.debug(f"normalized: {avg_per_entry[idx]}")

logger.line(f"Plot samples")

# Plot data
fig, ax = plt.subplots(figsize=(9,5), dpi=200)

if y_lims:
    ax.set_ylim(*y_lims)

if meta_data.legend:
    #Legend: target set: %d
    target_set = int(meta_data.legend.split(" ")[2])
    meta_data.legend += ", avg: " +  str(avg_per_entry[target_set])
    meta_data.legend += ", overall avg " + str(overall_avg)



x_vals = list(range(len(avg_per_entry)))
#print("X Vals", x_vals)
#min_per_entry = [0]*len(avg_per_entry)
#max_per_entry = [0]*len(avg_per_entry)
error_low = abs(min_per_entry-avg_per_entry)
error_high = abs(max_per_entry-avg_per_entry)
ax.errorbar(x_vals, avg_per_entry, (error_low,error_high ), label=meta_data.legend,
            fmt='-^', ms=5, capthick=.5, capsize=3, linestyle='None')
ax.scatter(x_vals[target_set], avg_per_entry[target_set],c=("red"))

# General settings
ax.set_title(f"Cache Side-Channel ({meta_data.samples_cnt} samples)")
ax.set_xlabel(meta_data.x_axis_label)
ax.set_ylabel(meta_data.y_axis_label)

if meta_data.legend:
    ax.legend(loc=1)

footnote = f"Trimming data to ({TRIM_LOW_PERCENTAGE}, {1 - TRIM_HIGH_PERCENTAGE})"
plt.text(0.75, 0.01, footnote, transform=plt.gcf().transFigure)

plot_name = log_file_name.rsplit(".", 1)[0] + "_plot.png"
plot_path = f"{output_folder}/{plot_name}"
logger.line(f"Save plot to {plot_path}")
plt.savefig(plot_path)

logger.line(f"Done")
