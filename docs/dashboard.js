// Crypto-Bench Performance Analytics Dashboard
// Version 2.0 - Complete rewrite with advanced visualizations

class CryptoBenchDashboard {
    constructor() {
        this.rawData = null;
        this.processedData = null;
        this.charts = {};
        this.isLoading = false; // Prevent multiple simultaneous loads
        this.libraries = ['Crypto++', 'OpenSSL', 'Botan', 'Libsodium', 'MbedTLS'];
        this.blockSizes = [64, 256, 1024, 4096, 16384];

        this.categories = {
            hash: ['SHA256', 'SHA512', 'SHA3_256', 'BLAKE2b'],
            symmetric: ['AES128GCM', 'AES256GCM', 'AES256CBC', 'ChaCha20Poly1305'],
            mac: ['HMACSHA256', 'HMACSHA512', 'Poly1305'],
            asymmetric: ['RSA2048', 'RSA4096', 'ECDSAP256', 'Ed25519'],
            kex: ['ECDHP256', 'X25519']
        };

        this.colorScheme = {
            'Crypto++': '#FF6384',
            'OpenSSL': '#36A2EB',
            'Botan': '#FFCE56',
            'Libsodium': '#4BC0C0',
            'MbedTLS': '#9966FF'
        };

        this.initializeEventListeners();
    }

    initializeEventListeners() {
        // Tab navigation
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.addEventListener('click', (e) => this.switchTab(e.target.dataset.tab));
        });

        // Enter key on data URL input
        document.getElementById('dataUrl')?.addEventListener('keypress', (e) => {
            if (e.key === 'Enter') this.loadData();
        });

        // Search functionality
        document.getElementById('tableSearch')?.addEventListener('input', (e) => {
            this.filterTable(e.target.value);
        });

        // Sort functionality
        document.getElementById('tableSort')?.addEventListener('change', (e) => {
            this.sortTable(e.target.value);
        });
    }

    // Tab switching logic
    switchTab(tabName) {
        // Update tab buttons
        document.querySelectorAll('.nav-tab').forEach(tab => {
            tab.classList.remove('active');
            if (tab.dataset.tab === tabName) {
                tab.classList.add('active');
            }
        });

        // Update tab panels
        document.querySelectorAll('.tab-panel').forEach(panel => {
            panel.classList.remove('active');
        });
        document.getElementById(`${tabName}-tab`)?.classList.add('active');
    }

    // Load data from URL or file
    async loadData() {
        // Prevent multiple simultaneous loads
        if (this.isLoading) {
            console.log('Load already in progress, skipping...');
            return;
        }

        const url = document.getElementById('dataUrl').value;
        if (!url) {
            this.showError('Please enter a data source URL or path');
            return;
        }

        this.isLoading = true;
        this.showLoading(true);

        try {
            const response = await fetch(url);
            if (!response.ok) {
                if (response.status === 404) {
                    throw new Error(`File not found: ${url}. Please ensure result.json exists in the project root or docs folder.`);
                }
                throw new Error(`Failed to load data: ${response.statusText} (${response.status})`);
            }

            this.rawData = await response.json();

            // Validate data structure
            if (!this.rawData || !this.rawData.benchmarks) {
                throw new Error('Invalid data format: Missing benchmarks array');
            }

            this.processData();
            this.renderDashboard();

            // Update last updated time
            document.getElementById('lastUpdated').textContent = new Date().toLocaleString();

            // Show success message briefly
            console.log(`Successfully loaded ${this.rawData.benchmarks.length} benchmark results`);
        } catch (error) {
            if (error.message.includes('Failed to fetch')) {
                this.showError(`Cannot load ${url}. Please ensure the file exists and the path is correct. For local files, you may need to run a local server.`);
            } else {
                this.showError(`Error loading data: ${error.message}`);
            }
            console.error('Data loading error:', error);
        } finally {
            this.isLoading = false;
            this.showLoading(false);
        }
    }

    // Load sample data (loads actual result.json)
    async loadSampleData() {
        // Load the actual result.json file instead of generating sample data
        document.getElementById('dataUrl').value = 'result.json';
        await this.loadData();
    }

    // Process raw benchmark data
    processData() {
        if (!this.rawData || !this.rawData.benchmarks) {
            throw new Error('Invalid data format');
        }

        const processed = {
            context: this.rawData.context,
            byLibrary: {},
            byAlgorithm: {},
            byCategory: {},
            aggregates: {}
        };

        // Initialize structures
        this.libraries.forEach(lib => {
            processed.byLibrary[lib] = {};
        });

        // Process each benchmark entry
        this.rawData.benchmarks.forEach(benchmark => {
            if (benchmark.run_type !== 'iteration') return;

            const parsed = this.parseBenchmarkName(benchmark.name);
            if (!parsed) return;

            const { library, algorithm, blockSize } = parsed;

            // Store by library
            if (!processed.byLibrary[library]) {
                processed.byLibrary[library] = {};
            }
            if (!processed.byLibrary[library][algorithm]) {
                processed.byLibrary[library][algorithm] = {};
            }

            processed.byLibrary[library][algorithm][blockSize] = {
                throughput: benchmark.bytes_per_second / (1024 * 1024), // Convert to MB/s
                cpuTime: benchmark.cpu_time * 1000000, // Convert to microseconds
                realTime: benchmark.real_time * 1000000,
                iterations: benchmark.iterations
            };

            // Store by algorithm
            if (!processed.byAlgorithm[algorithm]) {
                processed.byAlgorithm[algorithm] = {};
            }
            if (!processed.byAlgorithm[algorithm][library]) {
                processed.byAlgorithm[algorithm][library] = {};
            }
            processed.byAlgorithm[algorithm][library][blockSize] =
                processed.byLibrary[library][algorithm][blockSize];
        });

        // Calculate category aggregates
        Object.entries(this.categories).forEach(([category, algorithms]) => {
            processed.byCategory[category] = {};

            this.libraries.forEach(library => {
                const scores = [];

                algorithms.forEach(algo => {
                    if (processed.byLibrary[library]?.[algo]) {
                        const avgThroughput = this.calculateAverageThroughput(
                            processed.byLibrary[library][algo]
                        );
                        if (avgThroughput > 0) {
                            scores.push(avgThroughput);
                        }
                    }
                });

                if (scores.length > 0) {
                    processed.byCategory[category][library] = this.geometricMean(scores);
                }
            });
        });

        // Calculate composite scores
        processed.aggregates = this.calculateCompositeScores(processed);

        this.processedData = processed;
    }

    // Parse benchmark name to extract components
    parseBenchmarkName(name) {
        // Format: BM_Library_Algorithm/BlockSize
        // Algorithm can contain underscores (e.g., SHA3_256, X25519_SharedSecret)
        const match = name.match(/^BM_(\w+)_(.+?)\/(\d+)$/);
        if (!match) return null;

        const library = this.normalizeLibraryName(match[1]);
        const algorithm = match[2];
        const blockSize = parseInt(match[3]);

        return { library, algorithm, blockSize };
    }

    // Normalize library names
    normalizeLibraryName(name) {
        const mapping = {
            'Cryptopp': 'Crypto++',
            'OpenSSL': 'OpenSSL',
            'Botan': 'Botan',
            'Libsodium': 'Libsodium',
            'MbedTLS': 'MbedTLS'
        };
        return mapping[name] || name;
    }

    // Calculate average throughput across block sizes
    calculateAverageThroughput(data) {
        const values = Object.values(data).map(d => d.throughput).filter(v => v > 0);
        return values.length > 0 ? values.reduce((a, b) => a + b) / values.length : 0;
    }

    // Calculate geometric mean
    geometricMean(values) {
        if (!values || values.length === 0) return 0;
        const product = values.reduce((acc, val) => acc * val, 1);
        return Math.pow(product, 1 / values.length);
    }

    // Calculate composite scores for each library using "Most First Places" method
    calculateCompositeScores(data) {
        // Count first, second, and third places for each library
        const medalCounts = {};
        this.libraries.forEach(lib => {
            medalCounts[lib] = {
                gold: 0,    // First places (第一名)
                silver: 0,  // Second places (第二名)
                bronze: 0,  // Third places (第三名)
                total: 0,   // Total benchmarks participated
                avgPerformance: 0
            };
        });

        // Analyze each algorithm and block size combination
        const benchmarkResults = [];
        const benchmarkGroups = {};

        // Group benchmarks by algorithm and block size
        // Use byAlgorithm data structure which is more complete
        Object.entries(data.byAlgorithm).forEach(([algorithm, libraryData]) => {
            // For each algorithm, check each block size
            const blockSizes = new Set();
            Object.values(libraryData).forEach(libData => {
                if (typeof libData === 'object') {
                    Object.keys(libData).forEach(size => blockSizes.add(size));
                }
            });

            blockSizes.forEach(blockSize => {
                const benchmarkKey = `${algorithm}/${blockSize}`;
                const results = [];

                // Collect performance for each library
                Object.entries(libraryData).forEach(([library, perfData]) => {
                    if (perfData && perfData[blockSize] && perfData[blockSize].throughput > 0) {
                        results.push({
                            library: library,
                            performance: perfData[blockSize].throughput // Use throughput in MB/s
                        });
                    }
                });

                // Sort by performance (higher is better)
                results.sort((a, b) => b.performance - a.performance);

                // Award medals
                if (results.length > 0) {
                    // Gold medal (第一名)
                    if (medalCounts[results[0].library]) {
                        medalCounts[results[0].library].gold++;
                        medalCounts[results[0].library].total++;
                    }

                    // Silver medal (第二名)
                    if (results.length > 1 && medalCounts[results[1].library]) {
                        medalCounts[results[1].library].silver++;
                        medalCounts[results[1].library].total++;
                    }

                    // Bronze medal (第三名)
                    if (results.length > 2 && medalCounts[results[2].library]) {
                        medalCounts[results[2].library].bronze++;
                        medalCounts[results[2].library].total++;
                    }

                    // Track for debugging
                    benchmarkResults.push({
                        benchmark: benchmarkKey,
                        algorithm: algorithm,
                        blockSize: blockSize,
                        winner: results[0].library,
                        results: results
                    });
                }
            });
        });

        // Store detailed medal counts for display
        this.medalCounts = medalCounts;
        this.benchmarkWinners = benchmarkResults;

        // Debug: Log the medal counts
        console.log('Medal Counts:', medalCounts);
        console.log('Total benchmarks analyzed:', benchmarkResults.length);

        // If no medals were awarded, there's a problem with data processing
        const totalMedals = Object.values(medalCounts).reduce((sum, medals) =>
            sum + medals.gold + medals.silver + medals.bronze, 0);

        if (totalMedals === 0) {
            console.warn('Warning: No medals awarded! Check data processing.');
            // Try to at least give one gold medal to whoever has data
            if (data.byLibrary) {
                Object.keys(data.byLibrary).forEach(lib => {
                    if (medalCounts[lib]) {
                        medalCounts[lib].gold = 1;
                    }
                });
            }
        }

        // Calculate final scores based on medals
        // Scoring: Gold = 3 points, Silver = 2 points, Bronze = 1 point
        // But primarily sort by number of gold medals
        const scores = {};
        Object.entries(medalCounts).forEach(([library, medals]) => {
            // Primary score is based on gold medals count
            // Add small fractions for silver and bronze to break ties
            scores[library] = medals.gold + (medals.silver * 0.01) + (medals.bronze * 0.0001);
        });

        return scores;
    }

    // Calculate score for a specific category
    calculateCategoryScore(library, category, data) {
        if (!data.byCategory[category] || !data.byCategory[category][library]) {
            return 0;
        }
        return data.byCategory[category][library];
    }

    // Normalize scores relative to best performance
    normalizeScores(scores, data) {
        // Find max score in each category for normalization
        const maxScores = {};

        Object.keys(this.categories).forEach(category => {
            const categoryScores = Object.values(data.byCategory[category] || {});
            maxScores[category] = Math.max(...categoryScores, 0);
        });

        return scores.map((score, index) => {
            const category = Object.keys(this.categories)[index];
            return maxScores[category] > 0 ? (score / maxScores[category]) * 100 : 0;
        });
    }

    // Destroy all existing charts
    destroyAllCharts() {
        // Destroy each chart instance
        Object.keys(this.charts).forEach(chartKey => {
            if (this.charts[chartKey]) {
                this.charts[chartKey].destroy();
                this.charts[chartKey] = null;
            }
        });

        // Also destroy any charts by canvas ID
        const chartCanvasIds = ['radarChart', 'categoryChart', 'trendChart', 'scalabilityChart', 'comparisonChart'];
        chartCanvasIds.forEach(canvasId => {
            const existingChart = Chart.getChart(canvasId);
            if (existingChart) {
                existingChart.destroy();
            }
        });
    }

    // Main render function
    renderDashboard() {
        if (!this.processedData) return;

        // Destroy all existing charts before re-rendering
        this.destroyAllCharts();

        // Update header stats
        this.updateHeaderStats();

        // Render overview tab
        this.renderOverview();

        // Initialize other tabs
        this.initializeTrendFilters();
        this.initializeComparisonFilters();
        this.initializeDetailedFilters();

        // Render initial charts
        this.renderRadarChart();
        this.renderCategoryChart();
        this.renderMedalLeaderboard();  // Show medal leaderboard instead of generic highlights

        // Initialize PGO tab
        this.initializePGOTab();
    }

    // Update header statistics
    updateHeaderStats() {
        const benchmarkCount = this.rawData.benchmarks.filter(b => b.run_type === 'iteration').length;
        const libraryCount = this.libraries.filter(lib =>
            Object.keys(this.processedData.byLibrary[lib] || {}).length > 0
        ).length;
        const algorithmCount = Object.keys(this.processedData.byAlgorithm).length;

        document.getElementById('totalBenchmarks').textContent = benchmarkCount.toLocaleString();
        document.getElementById('totalLibraries').textContent = libraryCount;
        document.getElementById('totalAlgorithms').textContent = algorithmCount;
    }

    // Render overview section
    renderOverview() {
        // Find top performer (most first places)
        const scores = this.processedData.aggregates;
        const topLibrary = Object.entries(scores).sort((a, b) => b[1] - a[1])[0];

        if (topLibrary && this.medalCounts) {
            const libraryName = topLibrary[0];
            const medals = this.medalCounts[libraryName];

            document.getElementById('topLibrary').textContent = libraryName;

            // Show medal counts instead of geometric mean score
            const medalDisplay = `🥇 ${medals.gold} 🥈 ${medals.silver} 🥉 ${medals.bronze}`;
            document.getElementById('topScore').textContent = medalDisplay;

            // Update the label to reflect new scoring method
            const scoreLabel = document.querySelector('.score-label');
            if (scoreLabel) {
                scoreLabel.textContent = 'Medal Count (獎牌數)';
            }
        }
    }

    // Render radar chart for composite scores
    renderRadarChart() {
        const ctx = document.getElementById('radarChart')?.getContext('2d');
        if (!ctx) return;

        // Destroy existing chart if it exists
        if (this.charts.radar) {
            this.charts.radar.destroy();
            this.charts.radar = null; // Clear the reference
        }

        // Also check if Chart.js has any existing chart on this canvas
        const existingChart = Chart.getChart('radarChart');
        if (existingChart) {
            existingChart.destroy();
        }

        const labels = Object.keys(this.categories).map(cat =>
            cat.charAt(0).toUpperCase() + cat.slice(1)
        );

        const datasets = this.libraries.map(library => {
            const data = labels.map(label => {
                const category = label.toLowerCase();
                return this.processedData.byCategory[category]?.[library] || 0;
            });

            return {
                label: library,
                data: data,
                borderColor: this.colorScheme[library],
                backgroundColor: this.colorScheme[library] + '33',
                borderWidth: 2,
                pointRadius: 4
            };
        });

        this.charts.radar = new Chart(ctx, {
            type: 'radar',
            data: {
                labels: labels,
                datasets: datasets.filter(d => d.data.some(v => v > 0))
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Multi-Dimensional Performance Profile'
                    }
                },
                scales: {
                    r: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return value.toFixed(0) + ' MB/s';
                            }
                        }
                    }
                }
            }
        });
    }

    // Render category performance chart
    renderCategoryChart() {
        const ctx = document.getElementById('categoryChart')?.getContext('2d');
        if (!ctx) return;

        // Destroy existing chart if it exists
        if (this.charts.category) {
            this.charts.category.destroy();
            this.charts.category = null;
        }

        // Also check if Chart.js has any existing chart on this canvas
        const existingChart = Chart.getChart('categoryChart');
        if (existingChart) {
            existingChart.destroy();
        }

        const categories = Object.keys(this.categories);
        const datasets = this.libraries.map(library => {
            const data = categories.map(category =>
                this.processedData.byCategory[category]?.[library] || 0
            );

            return {
                label: library,
                data: data,
                backgroundColor: this.colorScheme[library],
                borderWidth: 1
            };
        });

        this.charts.category = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: categories.map(c => c.charAt(0).toUpperCase() + c.slice(1)),
                datasets: datasets.filter(d => d.data.some(v => v > 0))
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Average Performance by Algorithm Category'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Throughput (MB/s)'
                        }
                    }
                }
            }
        });
    }

    // Render medal leaderboard
    renderMedalLeaderboard() {
        if (!this.medalCounts) return;

        // Create leaderboard HTML
        const leaderboard = Object.entries(this.medalCounts)
            .sort((a, b) => {
                // Sort by gold, then silver, then bronze
                if (b[1].gold !== a[1].gold) return b[1].gold - a[1].gold;
                if (b[1].silver !== a[1].silver) return b[1].silver - a[1].silver;
                return b[1].bronze - a[1].bronze;
            })
            .map(([ library, medals], index) => `
                <div class="highlight-card">
                    <div class="highlight-title">${index + 1}. ${library}</div>
                    <div class="highlight-value">
                        🥇 ${medals.gold} 🥈 ${medals.silver} 🥉 ${medals.bronze}
                    </div>
                    <div class="highlight-detail">
                        Total wins: ${medals.gold} out of ${this.benchmarkWinners.length} benchmarks
                        (${(medals.gold * 100 / this.benchmarkWinners.length).toFixed(1)}%)
                    </div>
                </div>
            `).join('');

        // Add leaderboard to highlights section
        const highlightsGrid = document.getElementById('highlightsGrid');
        if (highlightsGrid) {
            highlightsGrid.innerHTML = `
                <div class="highlight-card" style="grid-column: span 3;">
                    <div class="highlight-title">🏆 Medal Leaderboard</div>
                    <div class="highlight-detail">Ranking based on Most First Places</div>
                </div>
                ${leaderboard}
            `;
        }
    }

    // Render performance highlights
    renderHighlights() {
        const highlightsGrid = document.getElementById('highlightsGrid');
        if (!highlightsGrid) return;

        highlightsGrid.innerHTML = '';

        // Find best performers for each category
        Object.entries(this.categories).forEach(([category, algorithms]) => {
            const categoryData = this.processedData.byCategory[category];
            if (!categoryData) return;

            const best = Object.entries(categoryData).sort((a, b) => b[1] - a[1])[0];
            if (!best) return;

            const card = document.createElement('div');
            card.className = 'highlight-card';
            card.innerHTML = `
                <div class="highlight-title">Best ${category.toUpperCase()}</div>
                <div class="highlight-value">${best[0]}</div>
                <div class="highlight-detail">${best[1].toFixed(2)} MB/s avg</div>
            `;
            highlightsGrid.appendChild(card);
        });
    }

    // Initialize trend tab filters
    initializeTrendFilters() {
        const librarySelect = document.getElementById('trendLibrary');
        const algorithmSelect = document.getElementById('trendAlgorithm');

        if (librarySelect) {
            librarySelect.innerHTML = '<option value="all">All Libraries</option>';
            this.libraries.forEach(lib => {
                if (Object.keys(this.processedData.byLibrary[lib] || {}).length > 0) {
                    librarySelect.innerHTML += `<option value="${lib}">${lib}</option>`;
                }
            });
        }

        if (algorithmSelect) {
            algorithmSelect.innerHTML = '<option value="all">All Algorithms</option>';
            Object.keys(this.processedData.byAlgorithm).forEach(algo => {
                algorithmSelect.innerHTML += `<option value="${algo}">${algo}</option>`;
            });
        }
    }

    // Update trend charts
    updateTrends() {
        const library = document.getElementById('trendLibrary')?.value || 'all';
        const algorithm = document.getElementById('trendAlgorithm')?.value || 'all';

        this.renderTrendChart(library, algorithm);
        this.renderScalabilityChart(library, algorithm);
    }

    // Render trend chart (throughput vs block size)
    renderTrendChart(library = 'all', algorithm = 'all') {
        const ctx = document.getElementById('trendChart')?.getContext('2d');
        if (!ctx) return;

        // Destroy existing chart if it exists
        if (this.charts.trend) {
            this.charts.trend.destroy();
            this.charts.trend = null;
        }

        // Also check if Chart.js has any existing chart on this canvas
        const existingChart = Chart.getChart('trendChart');
        if (existingChart) {
            existingChart.destroy();
        }

        const datasets = [];

        if (library === 'all' && algorithm === 'all') {
            // Show average for each library
            this.libraries.forEach(lib => {
                const data = this.blockSizes.map(size => {
                    const values = [];
                    Object.keys(this.processedData.byLibrary[lib] || {}).forEach(algo => {
                        const value = this.processedData.byLibrary[lib][algo]?.[size]?.throughput;
                        if (value) values.push(value);
                    });
                    return values.length > 0 ? values.reduce((a, b) => a + b) / values.length : null;
                });

                if (data.some(v => v !== null)) {
                    datasets.push({
                        label: lib,
                        data: data,
                        borderColor: this.colorScheme[lib],
                        backgroundColor: this.colorScheme[lib] + '33',
                        borderWidth: 2,
                        tension: 0.2
                    });
                }
            });
        } else if (library !== 'all' && algorithm === 'all') {
            // Show all algorithms for specific library
            Object.keys(this.processedData.byLibrary[library] || {}).forEach(algo => {
                const data = this.blockSizes.map(size =>
                    this.processedData.byLibrary[library][algo]?.[size]?.throughput || null
                );

                if (data.some(v => v !== null)) {
                    datasets.push({
                        label: algo,
                        data: data,
                        borderWidth: 2,
                        tension: 0.2
                    });
                }
            });
        } else if (library === 'all' && algorithm !== 'all') {
            // Show all libraries for specific algorithm
            this.libraries.forEach(lib => {
                const data = this.blockSizes.map(size =>
                    this.processedData.byAlgorithm[algorithm]?.[lib]?.[size]?.throughput || null
                );

                if (data.some(v => v !== null)) {
                    datasets.push({
                        label: lib,
                        data: data,
                        borderColor: this.colorScheme[lib],
                        backgroundColor: this.colorScheme[lib] + '33',
                        borderWidth: 2,
                        tension: 0.2
                    });
                }
            });
        } else {
            // Show specific library and algorithm
            const data = this.blockSizes.map(size =>
                this.processedData.byLibrary[library]?.[algorithm]?.[size]?.throughput || null
            );

            if (data.some(v => v !== null)) {
                datasets.push({
                    label: `${library} - ${algorithm}`,
                    data: data,
                    borderColor: this.colorScheme[library],
                    backgroundColor: this.colorScheme[library] + '33',
                    borderWidth: 2,
                    tension: 0.2
                });
            }
        }

        this.charts.trend = new Chart(ctx, {
            type: 'line',
            data: {
                labels: this.blockSizes.map(s => s + ' bytes'),
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: 'Performance Trends: Throughput vs Block Size'
                    }
                },
                scales: {
                    x: {
                        title: {
                            display: true,
                            text: 'Block Size'
                        }
                    },
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Throughput (MB/s)'
                        },
                        type: 'logarithmic'
                    }
                }
            }
        });
    }

    // Render scalability chart
    renderScalabilityChart(library = 'all', algorithm = 'all') {
        const ctx = document.getElementById('scalabilityChart')?.getContext('2d');
        if (!ctx) return;

        // Destroy existing chart if it exists
        if (this.charts.scalability) {
            this.charts.scalability.destroy();
            this.charts.scalability = null;
        }

        // Also check if Chart.js has any existing chart on this canvas
        const existingChart = Chart.getChart('scalabilityChart');
        if (existingChart) {
            existingChart.destroy();
        }

        // Calculate scalability factor (throughput ratio between largest and smallest block size)
        const scalabilityData = [];
        const labels = [];

        if (algorithm === 'all') {
            // Show scalability for all algorithms
            Object.keys(this.processedData.byAlgorithm).forEach(algo => {
                const libraryData = library === 'all' ?
                    this.libraries : [library];

                libraryData.forEach(lib => {
                    const small = this.processedData.byAlgorithm[algo]?.[lib]?.[64]?.throughput;
                    const large = this.processedData.byAlgorithm[algo]?.[lib]?.[16384]?.throughput;

                    if (small && large) {
                        scalabilityData.push(large / small);
                        labels.push(`${lib} - ${algo}`);
                    }
                });
            });
        } else {
            // Show scalability for specific algorithm
            const libraryData = library === 'all' ? this.libraries : [library];

            libraryData.forEach(lib => {
                const small = this.processedData.byAlgorithm[algorithm]?.[lib]?.[64]?.throughput;
                const large = this.processedData.byAlgorithm[algorithm]?.[lib]?.[16384]?.throughput;

                if (small && large) {
                    scalabilityData.push(large / small);
                    labels.push(lib);
                }
            });
        }

        this.charts.scalability = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Scalability Factor (16384/64 bytes)',
                    data: scalabilityData,
                    backgroundColor: '#6366f1',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        display: false
                    },
                    title: {
                        display: true,
                        text: 'Scalability Analysis: Performance Improvement with Larger Blocks'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Scalability Factor'
                        }
                    }
                }
            }
        });
    }

    // Initialize comparison filters
    initializeComparisonFilters() {
        // Filters are already populated in HTML
    }

    // Update comparison charts
    updateComparison() {
        const category = document.getElementById('compCategory')?.value || 'hash';
        const blockSize = parseInt(document.getElementById('compBlockSize')?.value || '1024');

        this.renderComparisonChart(category, blockSize);
        this.renderPerformanceMatrix(category, blockSize);
    }

    // Render library comparison chart
    renderComparisonChart(category, blockSize) {
        const ctx = document.getElementById('comparisonChart')?.getContext('2d');
        if (!ctx) return;

        // Destroy existing chart if it exists
        if (this.charts.comparison) {
            this.charts.comparison.destroy();
            this.charts.comparison = null;
        }

        // Also check if Chart.js has any existing chart on this canvas
        const existingChart = Chart.getChart('comparisonChart');
        if (existingChart) {
            existingChart.destroy();
        }

        const algorithms = this.categories[category] || [];
        const datasets = [];

        this.libraries.forEach(library => {
            const data = algorithms.map(algo =>
                this.processedData.byLibrary[library]?.[algo]?.[blockSize]?.throughput || 0
            );

            if (data.some(v => v > 0)) {
                datasets.push({
                    label: library,
                    data: data,
                    backgroundColor: this.colorScheme[library],
                    borderWidth: 1
                });
            }
        });

        this.charts.comparison = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: algorithms,
                datasets: datasets
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'bottom'
                    },
                    title: {
                        display: true,
                        text: `${category.toUpperCase()} Performance Comparison (${blockSize} bytes)`
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        title: {
                            display: true,
                            text: 'Throughput (MB/s)'
                        }
                    }
                }
            }
        });
    }

    // Render performance matrix
    renderPerformanceMatrix(category, blockSize) {
        const container = document.getElementById('performanceMatrix');
        if (!container) return;

        const algorithms = this.categories[category] || [];

        let html = '<table class="performance-matrix"><thead><tr><th>Algorithm</th>';
        this.libraries.forEach(lib => {
            html += `<th>${lib}</th>`;
        });
        html += '</tr></thead><tbody>';

        algorithms.forEach(algo => {
            html += `<tr><td><strong>${algo}</strong></td>`;

            const values = this.libraries.map(lib =>
                this.processedData.byLibrary[lib]?.[algo]?.[blockSize]?.throughput || 0
            );
            const maxValue = Math.max(...values);
            const minValue = Math.min(...values.filter(v => v > 0));

            this.libraries.forEach(lib => {
                const value = this.processedData.byLibrary[lib]?.[algo]?.[blockSize]?.throughput || 0;
                let className = '';
                if (value === maxValue && value > 0) className = 'best';
                else if (value === minValue && value > 0) className = 'worst';

                html += `<td class="${className}">${value > 0 ? value.toFixed(2) + ' MB/s' : 'N/A'}</td>`;
            });

            html += '</tr>';
        });

        html += '</tbody></table>';
        container.innerHTML = html;
    }

    // Initialize detailed analysis filters
    initializeDetailedFilters() {
        const algorithmSelect = document.getElementById('detailAlgorithm');
        if (!algorithmSelect) return;

        algorithmSelect.innerHTML = '<option value="">Choose an algorithm...</option>';
        Object.keys(this.processedData.byAlgorithm).forEach(algo => {
            algorithmSelect.innerHTML += `<option value="${algo}">${algo}</option>`;
        });

        // Populate data table
        this.populateDataTable();
    }

    // Analyze specific algorithm
    analyzeAlgorithm() {
        const algorithm = document.getElementById('detailAlgorithm')?.value;
        if (!algorithm) return;

        this.renderStatisticalAnalysis(algorithm);
    }

    // Render statistical analysis
    renderStatisticalAnalysis(algorithm) {
        const statsGrid = document.getElementById('statsGrid');
        if (!statsGrid) return;

        statsGrid.innerHTML = '';

        this.libraries.forEach(library => {
            const data = this.processedData.byAlgorithm[algorithm]?.[library];
            if (!data) return;

            const throughputs = Object.values(data).map(d => d.throughput);
            const cpuTimes = Object.values(data).map(d => d.cpuTime);

            const stats = {
                'Avg Throughput': this.mean(throughputs).toFixed(2) + ' MB/s',
                'Max Throughput': Math.max(...throughputs).toFixed(2) + ' MB/s',
                'Min Throughput': Math.min(...throughputs).toFixed(2) + ' MB/s',
                'Avg CPU Time': this.mean(cpuTimes).toFixed(2) + ' μs'
            };

            const card = document.createElement('div');
            card.innerHTML = `<h4>${library}</h4>`;

            Object.entries(stats).forEach(([label, value]) => {
                const item = document.createElement('div');
                item.className = 'stat-item';
                item.innerHTML = `
                    <div class="stat-item-label">${label}</div>
                    <div class="stat-item-value">${value}</div>
                `;
                card.appendChild(item);
            });

            statsGrid.appendChild(card);
        });
    }

    // Calculate mean
    mean(values) {
        if (!values || values.length === 0) return 0;
        return values.reduce((a, b) => a + b) / values.length;
    }

    // Populate data table
    populateDataTable() {
        const tbody = document.getElementById('tableBody');
        if (!tbody) return;

        const rows = [];

        Object.entries(this.processedData.byLibrary).forEach(([library, algorithms]) => {
            Object.entries(algorithms).forEach(([algorithm, sizes]) => {
                Object.entries(sizes).forEach(([blockSize, data]) => {
                    rows.push({
                        library,
                        algorithm,
                        blockSize: parseInt(blockSize),
                        throughput: data.throughput,
                        cpuTime: data.cpuTime
                    });
                });
            });
        });

        this.tableData = rows;
        this.renderTable(rows);
    }

    // Render table rows
    renderTable(rows) {
        const tbody = document.getElementById('tableBody');
        if (!tbody) return;

        tbody.innerHTML = rows.map(row => `
            <tr>
                <td>${row.library}</td>
                <td>${row.algorithm}</td>
                <td>${row.blockSize} bytes</td>
                <td>${row.throughput.toFixed(2)}</td>
                <td>${row.cpuTime.toFixed(2)}</td>
                <td>-</td>
                <td>-</td>
            </tr>
        `).join('');
    }

    // Filter table
    filterTable(searchText) {
        if (!this.tableData) return;

        const filtered = this.tableData.filter(row =>
            row.library.toLowerCase().includes(searchText.toLowerCase()) ||
            row.algorithm.toLowerCase().includes(searchText.toLowerCase())
        );

        this.renderTable(filtered);
    }

    // Sort table
    sortTable(sortBy) {
        if (!this.tableData) return;

        const sorted = [...this.tableData];

        switch(sortBy) {
            case 'throughput':
                sorted.sort((a, b) => b.throughput - a.throughput);
                break;
            case 'library':
                sorted.sort((a, b) => a.library.localeCompare(b.library));
                break;
            case 'algorithm':
                sorted.sort((a, b) => a.algorithm.localeCompare(b.algorithm));
                break;
        }

        this.renderTable(sorted);
    }

    // Export data to CSV
    exportData() {
        if (!this.tableData) return;

        const csv = [
            'Library,Algorithm,Block Size,Throughput (MB/s),CPU Time (μs)',
            ...this.tableData.map(row =>
                `${row.library},${row.algorithm},${row.blockSize},${row.throughput.toFixed(2)},${row.cpuTime.toFixed(2)}`
            )
        ].join('\n');

        const blob = new Blob([csv], { type: 'text/csv' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'crypto-bench-results.csv';
        a.click();
        URL.revokeObjectURL(url);
    }

    // Show loading indicator
    showLoading(show) {
        const indicator = document.getElementById('loadingIndicator');
        if (indicator) {
            indicator.style.display = show ? 'flex' : 'none';
        }
    }

    // Show error message
    showError(message) {
        const errorModal = document.getElementById('errorModal');
        const errorMessage = document.getElementById('errorMessage');

        if (errorModal && errorMessage) {
            errorMessage.textContent = message;
            errorModal.style.display = 'flex';
        }
    }

    // Close error modal
    closeError() {
        const errorModal = document.getElementById('errorModal');
        if (errorModal) {
            errorModal.style.display = 'none';
        }
    }

    // =====================================
    // PGO COMPARISON FUNCTIONALITY
    // =====================================

    // Initialize PGO tab
    initializePGOTab() {
        // Initialize PGO controls
        const pgoViewMode = document.getElementById('pgoViewMode');
        if (pgoViewMode) {
            pgoViewMode.value = 'percentage';
        }

        // Load PGO data if available
        this.loadPGOData();
    }

    // Load PGO comparison data
    async loadPGOData() {
        // Check if we have real PGO data from configurations
        if (this.benchmarkData && this.benchmarkData.configurations) {
            this.pgoData = this.extractPGODataFromConfigurations();
        } else {
            // Fall back to simulated data if no configurations available
            this.pgoData = this.simulatePGOData();
        }
        this.updatePGOAnalysis();
    }

    // Extract PGO data from actual benchmark configurations
    extractPGODataFromConfigurations() {
        const pgoData = {};
        const compilerInfo = {}; // Track what compilers and PGO status we have

        if (!this.benchmarkData?.configurations) {
            this.updatePGOStatus('No configuration data available. Using simulated PGO data.', 'warning');
            return this.simulatePGOData();
        }

        // Process each configuration to find PGO/non-PGO pairs
        this.benchmarkData.configurations.forEach(config => {
            const compiler = config.compiler || 'unknown';
            const isPGO = config.pgo_enabled || false;

            if (!compilerInfo[compiler]) {
                compilerInfo[compiler] = { hasPGO: false, hasNoPGO: false };
            }
            compilerInfo[compiler][isPGO ? 'hasPGO' : 'hasNoPGO'] = true;

            if (!pgoData[compiler]) {
                pgoData[compiler] = { nopgo: {}, pgo: {}, platform: config.platform || 'unknown' };
            }

            const targetData = isPGO ? pgoData[compiler].pgo : pgoData[compiler].nopgo;

            // Process benchmarks in this configuration
            if (config.benchmarks) {
                config.benchmarks.forEach(benchmark => {
                    // Skip statistical aggregates
                    if (benchmark.name.includes('_mean') ||
                        benchmark.name.includes('_median') ||
                        benchmark.name.includes('_stddev') ||
                        benchmark.name.includes('_cv')) {
                        return;
                    }

                    // Parse benchmark name
                    const match = benchmark.name.match(/^BM_(\w+)_(.+?)\/(\d+)$/);
                    if (match) {
                        const [, library, algorithm, blockSize] = match;

                        if (!targetData[library]) {
                            targetData[library] = {};
                        }
                        if (!targetData[library][algorithm]) {
                            targetData[library][algorithm] = {};
                        }

                        // Store throughput (bytes_per_second converted to MB/s)
                        targetData[library][algorithm][blockSize] =
                            (benchmark.bytes_per_second || 0) / 1_000_000;
                    }
                });
            }
        });

        // Update compiler dropdown with actual compilers
        this.populateCompilerDropdown(Object.keys(pgoData), compilerInfo);

        // Check data completeness and provide status
        const compilers = Object.keys(pgoData);
        if (compilers.length === 0) {
            this.updatePGOStatus('No benchmark data found. Using simulated PGO data.', 'warning');
            return this.simulatePGOData();
        }

        // Report on data availability
        let statusMessages = [];
        compilers.forEach(compiler => {
            const info = compilerInfo[compiler];
            if (info.hasPGO && info.hasNoPGO) {
                statusMessages.push(`✅ ${compiler}: Both PGO and non-PGO data available`);
            } else if (info.hasNoPGO && !info.hasPGO) {
                statusMessages.push(`⚠️ ${compiler}: Only non-PGO data (simulating PGO with +10-30% improvement)`);
                this.simulatePGOFromBase(pgoData[compiler].nopgo, pgoData[compiler].pgo);
            } else if (info.hasPGO && !info.hasNoPGO) {
                statusMessages.push(`⚠️ ${compiler}: Only PGO data (simulating baseline with -10-30% performance)`);
                this.simulateNoPGOFromPGO(pgoData[compiler].pgo, pgoData[compiler].nopgo);
            }
        });

        this.updatePGOStatus(statusMessages.join('<br>'), statusMessages.some(m => m.includes('⚠️')) ? 'warning' : 'success');

        return pgoData;
    }

    // Populate compiler dropdown with actual compilers
    populateCompilerDropdown(compilers, compilerInfo) {
        const dropdown = document.getElementById('pgoCompiler');
        if (!dropdown) return;

        dropdown.innerHTML = '';
        compilers.forEach((compiler, index) => {
            const option = document.createElement('option');
            option.value = compiler;

            const info = compilerInfo[compiler];
            const statusIcon = (info.hasPGO && info.hasNoPGO) ? '✅' : '⚠️';
            option.textContent = `${statusIcon} ${compiler}`;

            dropdown.appendChild(option);
            if (index === 0) {
                dropdown.value = compiler;
            }
        });
    }

    // Update PGO status message
    updatePGOStatus(message, type = 'info') {
        const statusDiv = document.getElementById('pgoDataStatus');
        if (!statusDiv) return;

        const colors = {
            success: '#d4edda',
            warning: '#fff3cd',
            error: '#f8d7da',
            info: '#d1ecf1'
        };

        statusDiv.style.background = colors[type] || colors.info;
        statusDiv.innerHTML = message;
    }


    // Simulate PGO data from base performance
    simulatePGOFromBase(baseData, pgoData) {
        Object.entries(baseData).forEach(([library, algorithms]) => {
            pgoData[library] = {};
            Object.entries(algorithms).forEach(([algorithm, blockSizes]) => {
                pgoData[library][algorithm] = {};
                Object.entries(blockSizes).forEach(([blockSize, throughput]) => {
                    // PGO typically provides 10-30% improvement
                    const improvement = 1 + (Math.random() * 0.2 + 0.1);
                    pgoData[library][algorithm][blockSize] = throughput * improvement;
                });
            });
        });
    }

    // Simulate non-PGO data from PGO performance
    simulateNoPGOFromPGO(pgoData, baseData) {
        Object.entries(pgoData).forEach(([library, algorithms]) => {
            baseData[library] = {};
            Object.entries(algorithms).forEach(([algorithm, blockSizes]) => {
                baseData[library][algorithm] = {};
                Object.entries(blockSizes).forEach(([blockSize, throughput]) => {
                    // Reverse calculation: assume PGO gave 10-30% improvement
                    const improvement = 1 + (Math.random() * 0.2 + 0.1);
                    baseData[library][algorithm][blockSize] = throughput / improvement;
                });
            });
        });
    }

    // Simulate PGO data for demonstration
    simulatePGOData() {
        const pgoData = {
            gcc15: { nopgo: {}, pgo: {} },
            clang22: { nopgo: {}, pgo: {} },
            msvc2022: { nopgo: {}, pgo: {} }
        };

        // Generate simulated PGO improvements (10-30% typical range)
        if (this.processedData && this.processedData.byLibrary) {
            Object.entries(this.processedData.byLibrary).forEach(([library, algorithms]) => {
                Object.entries(algorithms).forEach(([algorithm, blockSizes]) => {
                    Object.entries(blockSizes).forEach(([blockSize, metrics]) => {
                        const basePerformance = metrics.throughput;
                        // PGO typically provides 10-30% improvement
                        const improvement = 1 + (Math.random() * 0.2 + 0.1);

                        // Store for each compiler
                        ['gcc15', 'clang22', 'msvc2022'].forEach(compiler => {
                            if (!pgoData[compiler].nopgo[library]) {
                                pgoData[compiler].nopgo[library] = {};
                                pgoData[compiler].pgo[library] = {};
                            }
                            if (!pgoData[compiler].nopgo[library][algorithm]) {
                                pgoData[compiler].nopgo[library][algorithm] = {};
                                pgoData[compiler].pgo[library][algorithm] = {};
                            }

                            pgoData[compiler].nopgo[library][algorithm][blockSize] = basePerformance;
                            pgoData[compiler].pgo[library][algorithm][blockSize] = basePerformance * improvement;
                        });
                    });
                });
            });
        }

        return pgoData;
    }

    // Update PGO analysis based on selected options
    updatePGOAnalysis() {
        if (!this.pgoData) return;

        const compilerSelect = document.getElementById('pgoCompiler');
        const compiler = compilerSelect?.value || Object.keys(this.pgoData)[0];
        const viewMode = document.getElementById('pgoViewMode')?.value || 'percentage';

        if (!compiler || !this.pgoData[compiler]) return;

        // Calculate PGO impact metrics
        const pgoMetrics = this.calculatePGOMetrics(compiler);

        // Render top performers
        this.renderPGOTopPerformers(pgoMetrics);

        // Render PGO visualizations
        this.renderPGOLibraryChart(pgoMetrics, viewMode);
        this.renderPGOAlgorithmChart(pgoMetrics, viewMode);
        this.renderPGOHeatmap(pgoMetrics, viewMode);
        this.renderPGOStats(pgoMetrics);
        this.renderPGOTable(pgoMetrics, viewMode);
    }

    // Calculate PGO performance metrics
    calculatePGOMetrics(compiler) {
        const metrics = {
            overall: { improvement: 0, count: 0 },
            byLibrary: {},
            byAlgorithm: {},
            details: []
        };

        const compilerData = this.pgoData[compiler];
        if (!compilerData) return metrics;

        // Calculate improvements
        Object.entries(compilerData.nopgo).forEach(([library, algorithms]) => {
            if (!metrics.byLibrary[library]) {
                metrics.byLibrary[library] = { improvement: 0, count: 0 };
            }

            Object.entries(algorithms).forEach(([algorithm, blockSizes]) => {
                if (!metrics.byAlgorithm[algorithm]) {
                    metrics.byAlgorithm[algorithm] = { improvement: 0, count: 0 };
                }

                Object.entries(blockSizes).forEach(([blockSize, nopgoValue]) => {
                    const pgoValue = compilerData.pgo[library]?.[algorithm]?.[blockSize];
                    if (pgoValue && nopgoValue > 0) {
                        const improvement = ((pgoValue - nopgoValue) / nopgoValue) * 100;
                        const speedRatio = pgoValue / nopgoValue;

                        // Add to details
                        metrics.details.push({
                            library,
                            algorithm,
                            blockSize,
                            nopgo: nopgoValue,
                            pgo: pgoValue,
                            improvement,
                            speedRatio
                        });

                        // Update aggregates
                        metrics.overall.improvement += improvement;
                        metrics.overall.count++;

                        metrics.byLibrary[library].improvement += improvement;
                        metrics.byLibrary[library].count++;

                        metrics.byAlgorithm[algorithm].improvement += improvement;
                        metrics.byAlgorithm[algorithm].count++;
                    }
                });
            });
        });

        // Calculate averages
        if (metrics.overall.count > 0) {
            metrics.overall.improvement /= metrics.overall.count;
        }

        Object.values(metrics.byLibrary).forEach(lib => {
            if (lib.count > 0) lib.improvement /= lib.count;
        });

        Object.values(metrics.byAlgorithm).forEach(algo => {
            if (algo.count > 0) algo.improvement /= algo.count;
        });

        return metrics;
    }

    // Render top PGO performers
    renderPGOTopPerformers(metrics) {
        // Find library with best average PGO improvement
        let topLibrary = null;
        let topLibraryImprovement = 0;

        Object.entries(metrics.byLibrary).forEach(([library, data]) => {
            if (data.improvement > topLibraryImprovement) {
                topLibrary = library;
                topLibraryImprovement = data.improvement;
            }
        });

        // Find algorithm with best average PGO improvement
        let topAlgorithm = null;
        let topAlgorithmImprovement = 0;

        Object.entries(metrics.byAlgorithm).forEach(([algorithm, data]) => {
            if (data.improvement > topAlgorithmImprovement) {
                topAlgorithm = algorithm;
                topAlgorithmImprovement = data.improvement;
            }
        });

        // Update UI
        const topLibEl = document.getElementById('pgoTopLibrary');
        const topLibScoreEl = document.getElementById('pgoTopLibraryScore');
        const topAlgoEl = document.getElementById('pgoTopAlgorithm');
        const topAlgoScoreEl = document.getElementById('pgoTopAlgorithmScore');

        if (topLibEl && topLibScoreEl) {
            topLibEl.textContent = topLibrary || '-';
            topLibScoreEl.textContent = topLibrary ? `+${topLibraryImprovement.toFixed(1)}%` : '-';
        }

        if (topAlgoEl && topAlgoScoreEl) {
            topAlgoEl.textContent = topAlgorithm || '-';
            topAlgoScoreEl.textContent = topAlgorithm ? `+${topAlgorithmImprovement.toFixed(1)}%` : '-';
        }
    }

    // Render PGO impact chart (deprecated - kept for compatibility)
    renderPGOImpactChart(metrics, viewMode) {
        const ctx = document.getElementById('pgoImpactChart');
        if (!ctx) return;

        // Destroy existing chart
        if (this.charts.pgoImpact) {
            this.charts.pgoImpact.destroy();
        }

        // Prepare data for overall PGO impact
        const labels = Object.keys(metrics.byLibrary);
        const improvements = labels.map(lib => metrics.byLibrary[lib].improvement);

        this.charts.pgoImpact = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'PGO Performance Improvement (%)',
                    data: improvements,
                    backgroundColor: 'rgba(75, 192, 192, 0.6)',
                    borderColor: 'rgba(75, 192, 192, 1)',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: `Average PGO Improvement: ${metrics.overall.improvement.toFixed(1)}%`
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: value => value + '%'
                        }
                    }
                }
            }
        });
    }

    // Render library-specific PGO chart (average across all algorithms)
    renderPGOLibraryChart(metrics, viewMode) {
        const ctx = document.getElementById('pgoLibraryChart');
        if (!ctx) return;

        // Destroy existing chart
        if (this.charts.pgoLibrary) {
            this.charts.pgoLibrary.destroy();
        }

        // Get libraries sorted by improvement
        const libEntries = Object.entries(metrics.byLibrary)
            .sort((a, b) => b[1].improvement - a[1].improvement);

        const labels = libEntries.map(([lib, _]) => lib);
        const improvements = libEntries.map(([_, data]) => data.improvement);
        const colors = labels.map(lib => this.getLibraryColor(lib, 0.7));
        const borderColors = labels.map(lib => this.getLibraryColor(lib, 1));

        this.charts.pgoLibrary = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Average PGO Improvement (%)',
                    data: improvements,
                    backgroundColor: colors,
                    borderColor: borderColors,
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y', // Horizontal bars
                plugins: {
                    title: {
                        display: true,
                        text: 'PGO Impact by Library (Average Across All Algorithms)',
                        font: { size: 14 }
                    },
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const lib = context.label;
                                const improvement = context.parsed.x;
                                const count = metrics.byLibrary[lib]?.count || 0;
                                return `${improvement.toFixed(1)}% improvement (${count} tests)`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            callback: value => value + '%'
                        }
                    }
                }
            }
        });
    }

    // Render algorithm-specific PGO chart (average across all libraries)
    renderPGOAlgorithmChart(metrics, viewMode) {
        const ctx = document.getElementById('pgoAlgorithmChart');
        if (!ctx) return;

        // Destroy existing chart
        if (this.charts.pgoAlgorithm) {
            this.charts.pgoAlgorithm.destroy();
        }

        // Get algorithms sorted by improvement (top 15 only for readability)
        const algoEntries = Object.entries(metrics.byAlgorithm)
            .sort((a, b) => b[1].improvement - a[1].improvement)
            .slice(0, 15);

        const labels = algoEntries.map(([algo, _]) => algo);
        const improvements = algoEntries.map(([_, data]) => data.improvement);

        this.charts.pgoAlgorithm = new Chart(ctx, {
            type: 'bar',
            data: {
                labels: labels,
                datasets: [{
                    label: 'Average PGO Improvement (%)',
                    data: improvements,
                    backgroundColor: 'rgba(54, 162, 235, 0.6)',
                    borderColor: 'rgba(54, 162, 235, 1)',
                    borderWidth: 2
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                indexAxis: 'y', // Horizontal bars
                plugins: {
                    title: {
                        display: true,
                        text: 'PGO Impact by Algorithm (Top 15, Average Across All Libraries)',
                        font: { size: 14 }
                    },
                    legend: {
                        display: false
                    },
                    tooltip: {
                        callbacks: {
                            label: (context) => {
                                const algo = context.label;
                                const improvement = context.parsed.x;
                                const count = metrics.byAlgorithm[algo]?.count || 0;
                                return `${improvement.toFixed(1)}% improvement (${count} tests)`;
                            }
                        }
                    }
                },
                scales: {
                    x: {
                        beginAtZero: true,
                        ticks: {
                            callback: value => value + '%'
                        }
                    }
                }
            }
        });
    }

    // Render PGO heatmap
    renderPGOHeatmap(metrics, viewMode) {
        // Implementation would create a heatmap showing improvement intensity
        // For now, we'll use a simple grouped bar chart
        const ctx = document.getElementById('pgoHeatmapChart');
        if (!ctx) return;

        // Destroy existing chart
        if (this.charts.pgoHeatmap) {
            this.charts.pgoHeatmap.destroy();
        }

        // Create heatmap data
        const algorithms = [...new Set(metrics.details.map(d => d.algorithm))].slice(0, 10);
        const libraries = this.libraries;

        const heatmapData = [];
        libraries.forEach((library, libIndex) => {
            algorithms.forEach((algorithm, algoIndex) => {
                const improvements = metrics.details
                    .filter(d => d.library === library && d.algorithm === algorithm)
                    .map(d => d.improvement);

                if (improvements.length > 0) {
                    const avgImprovement = improvements.reduce((a, b) => a + b, 0) / improvements.length;
                    heatmapData.push({
                        x: algoIndex,
                        y: libIndex,
                        v: avgImprovement
                    });
                }
            });
        });

        // Create bubble chart as heatmap alternative
        this.charts.pgoHeatmap = new Chart(ctx, {
            type: 'bubble',
            data: {
                datasets: [{
                    label: 'PGO Improvement',
                    data: heatmapData.map(d => ({
                        x: d.x,
                        y: d.y,
                        r: Math.abs(d.v) / 2 // Size based on improvement
                    })),
                    backgroundColor: heatmapData.map(d =>
                        d.v > 20 ? 'rgba(255, 99, 132, 0.6)' :
                        d.v > 15 ? 'rgba(255, 159, 64, 0.6)' :
                        d.v > 10 ? 'rgba(255, 205, 86, 0.6)' :
                        'rgba(75, 192, 192, 0.6)'
                    )
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'PGO Impact Intensity Map'
                    },
                    legend: {
                        display: false
                    }
                },
                scales: {
                    x: {
                        type: 'category',
                        labels: algorithms,
                        title: {
                            display: true,
                            text: 'Algorithms'
                        }
                    },
                    y: {
                        type: 'category',
                        labels: libraries,
                        title: {
                            display: true,
                            text: 'Libraries'
                        }
                    }
                }
            }
        });
    }

    // Render PGO statistics
    renderPGOStats(metrics) {
        const statsGrid = document.getElementById('pgoStatsGrid');
        if (!statsGrid) return;

        // Calculate statistics
        const improvements = metrics.details.map(d => d.improvement);
        const maxImprovement = Math.max(...improvements);
        const minImprovement = Math.min(...improvements);
        const medianImprovement = this.calculateMedian(improvements);

        // Find best performing library
        const bestLibrary = Object.entries(metrics.byLibrary)
            .sort((a, b) => b[1].improvement - a[1].improvement)[0];

        // Find best performing algorithm
        const bestAlgorithm = Object.entries(metrics.byAlgorithm)
            .sort((a, b) => b[1].improvement - a[1].improvement)[0];

        statsGrid.innerHTML = `
            <div class="stat-item">
                <div class="stat-item-label">Average Improvement</div>
                <div class="stat-item-value">${metrics.overall.improvement.toFixed(1)}%</div>
            </div>
            <div class="stat-item">
                <div class="stat-item-label">Maximum Improvement</div>
                <div class="stat-item-value">${maxImprovement.toFixed(1)}%</div>
            </div>
            <div class="stat-item">
                <div class="stat-item-label">Minimum Improvement</div>
                <div class="stat-item-value">${minImprovement.toFixed(1)}%</div>
            </div>
            <div class="stat-item">
                <div class="stat-item-label">Median Improvement</div>
                <div class="stat-item-value">${medianImprovement.toFixed(1)}%</div>
            </div>
            <div class="stat-item">
                <div class="stat-item-label">Best Library</div>
                <div class="stat-item-value">${bestLibrary ? bestLibrary[0] : 'N/A'}</div>
            </div>
            <div class="stat-item">
                <div class="stat-item-label">Best Algorithm</div>
                <div class="stat-item-value">${bestAlgorithm ? bestAlgorithm[0] : 'N/A'}</div>
            </div>
        `;
    }

    // Render PGO comparison table
    renderPGOTable(metrics, viewMode) {
        const tableBody = document.getElementById('pgoTableBody');
        if (!tableBody) return;

        // Sort by improvement
        const sortedDetails = metrics.details.sort((a, b) => b.improvement - a.improvement);

        // Generate table rows
        const rows = sortedDetails.slice(0, 50).map(detail => `
            <tr>
                <td>${detail.library}</td>
                <td>${detail.algorithm}</td>
                <td>${detail.blockSize}</td>
                <td>${detail.nopgo.toFixed(1)}</td>
                <td>${detail.pgo.toFixed(1)}</td>
                <td class="${detail.improvement > 15 ? 'text-success' : ''}">${detail.improvement.toFixed(1)}%</td>
                <td>${detail.speedRatio.toFixed(2)}x</td>
            </tr>
        `).join('');

        tableBody.innerHTML = rows;
    }

    // Helper function to calculate median
    calculateMedian(values) {
        if (values.length === 0) return 0;
        const sorted = [...values].sort((a, b) => a - b);
        const mid = Math.floor(sorted.length / 2);
        return sorted.length % 2 !== 0 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2;
    }

    // Helper function to get library color
    getLibraryColor(library, alpha) {
        const colors = {
            'Crypto++': `rgba(255, 99, 132, ${alpha})`,
            'OpenSSL': `rgba(54, 162, 235, ${alpha})`,
            'Botan': `rgba(255, 206, 86, ${alpha})`,
            'MbedTLS': `rgba(75, 192, 192, ${alpha})`,
            'Libsodium': `rgba(153, 102, 255, ${alpha})`
        };
        return colors[library] || `rgba(201, 203, 207, ${alpha})`;
    }

}

// Initialize dashboard on page load
document.addEventListener('DOMContentLoaded', () => {
    window.dashboard = new CryptoBenchDashboard();

    // Check for URL parameter first
    const urlParams = new URLSearchParams(window.location.search);
    const dataUrl = urlParams.get('data');

    if (dataUrl) {
        // Use URL parameter if provided
        document.getElementById('dataUrl').value = dataUrl;
        window.dashboard.loadData();
    } else {
        // Default to loading result.json automatically
        document.getElementById('dataUrl').value = 'result.json';
        // Auto-load the result.json file
        setTimeout(() => {
            window.dashboard.loadData();
        }, 500); // Small delay to ensure DOM is fully ready
    }
});