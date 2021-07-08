using System;
using System.Diagnostics;
using System.Globalization;
using System.Threading;
using NUnit.Framework;
using VSharp.Interpreter.IL;

namespace VSharp.Test
{
    [SetUpFixture]
    public class SetUpSvm
    {
        [OneTimeSetUp]
        public void PrepareSvm()
        {
            Trace.Listeners.Add(new Utils.DumpStackTraceListener());

            var ci = new CultureInfo("en-GB")
            {
                NumberFormat = {
                    PositiveInfinitySymbol = "Infinity",
                    NegativeInfinitySymbol = "-Infinity"
                }
            };
            Thread.CurrentThread.CurrentCulture = ci;

            uint maxBound = 15;
            // var svm = new SVM(new VSharp.Analyzer.StepInterpreter());
            Logger.ConfigureWriter(TestContext.Progress);
            // var svm = new SVM(new PobsInterpreter(new BFSSearcher(bound)));
            var svm = new SVM(new PobsInterpreter(maxBound, new DFSSearcher()));
            // var svm = new SVM(new PobsInterpreter(new TargetedSearcher(bound)));
            // var svm = new SVM(new MethodInterpreter(maxBound, new DFSSearcher()));
            svm.ConfigureSolver();
            // SVM.ConfigureSimplifier(new Z3Simplifier()); can be used to enable Z3-based simplification (not recommended)
            var searchers = new INewSearcher[] {
                // new BidirectionalSearcherForMethods()
                new DFSSearcher()
                // , new DFSSearcher()
                // , new BFSSearcher()
                // , new BFSSearcher()
                // , new BidirectionalSearcherForMethods()
                // , new BidirectionalSearcherForMethods()
                // new TargetedSearcher(maxBound)
            };
            //var pobsStatistics = new PobsStatistics(searchers);
            TestSvmAttribute.SetUpSVM(svm, maxBound, searchers);
        }

        [OneTimeTearDown]
        public void PrintStats()
        {
            TestSvmAttribute.PrintStats();
        }

    }
}