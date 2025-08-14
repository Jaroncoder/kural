// static/js/main.js
document.addEventListener('DOMContentLoaded', () => {
	document.body.classList.add('loaded');

	const gpsBtn = document.getElementById('btn-gps');
	if (gpsBtn) {
		const statusEl = document.getElementById('gps-status');
		const latEl = document.getElementById('latitude');
		const lngEl = document.getElementById('longitude');
		gpsBtn.addEventListener('click', () => {
			if (!navigator.geolocation) {
				statusEl.textContent = 'Geolocation not supported.';
				return;
			}
			statusEl.textContent = 'Fetching GPS...';
			navigator.geolocation.getCurrentPosition(
				(pos) => {
					const { latitude, longitude } = pos.coords;
					latEl.value = latitude.toFixed(6);
					lngEl.value = longitude.toFixed(6);
					statusEl.textContent = `Lat ${latEl.value}, Lng ${lngEl.value}`;
				},
				(err) => {
					statusEl.textContent = 'Unable to fetch location.';
				},
				{ enableHighAccuracy: true, timeout: 8000, maximumAge: 0 }
			);
		});
	}
});