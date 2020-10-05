module NdrPseudonymise
  # Log percentage progress on pseudonymisation
  # Starts logging after 1 minute or 5%, then at 5% / 5 minute intervals
  class ProgressPrinter
    # Logs progress to the given stream (default $stdout)
    # If verbose = false, only log percentages on a single line
    # If verbose = true, log verbose output
    # If verbose = :dynamic, act like verbose = false, but if the total time is
    # more than 5 minutes, move into verbose = true mode
    def initialize(dest = $stdout, verbose = false)
      @dest = dest
      @verbose = verbose
      @last_percent = 0
      @last_log = Time.current - (60 * 4) # First log entry after 1 minute
    end

    # Returns a lambda that prints progress to stdout (or another stream).
    # parameter _csv_row is not used.
    def log_progress(start_time, time_now, _csv_row, progress, total)
      current_percentage = total == 0 ? 0 : (progress * 100 / total).to_i
      now = Time.current
      if (current_percentage / 5 > @last_percent / 5) || # Log at 5% / 5 minute intervals
         (now - @last_log >= 60 * 5) || current_percentage == 100
        if @verbose == :dynamic && (time_now - start_time >= 60 * 5)
          @verbose = true
          @dest << '...'
        end
        if @verbose == true
          # TODO: Add estimated completion time
          tfin = if progress > 0
                   time_now + (time_now - start_time) * (total - progress) / progress
                 end
          completion = tfin ? ', expected completion' : ''
          @dest << format("Completed %s%% in %.1f minutes%s\n",
                          current_percentage, (now - start_time) / 60.0, completion)

          # @dest << ("Completed %s%% in %.1f minutes#{", expected completion #{tfin}" if tfin}\n" %
          #            [current_percentage, (now - start_time) / 60.0])

        else
          @dest << "#{'...' if @last_percent > 0}#{current_percentage}%"
          @dest << "\n" if current_percentage == 100
        end
        # if current_percentage == 100 # Uncomment for performance debugging
        #   @dest << "Finished %s rows in %.3f secs\n" % [csv_row, time_now - start_time]
        # end
        @dest.flush
        @last_percent = current_percentage
        @last_log = now
      end
    end
  end
end
